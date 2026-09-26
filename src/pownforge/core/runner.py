from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Callable

from pownforge.core.concurrency import ConcurrencyError, ConcurrencyGuard
from pownforge.core.finding_utils import coerce_finding
from pownforge.core.models import Evidence, ExecutionRequest, ExecutionResult, Finding, RunRecord, Target
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.process import ProcessExecutor, ProcessLimitError, execution_result_from_process
from pownforge.core.registry import PluginRegistry
from pownforge.core.secrets import mask_command
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.hashing import sha256_text
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginExecution

OnLine = Callable[[str], None]


class RunnerError(RuntimeError):
    """Raised when a scan cannot be executed. Also raised (wrapping the
    original ConcurrencyError, see core/concurrency.py) when a target's
    max_concurrent limit is already reached -- callers that already catch
    RunnerError don't need to learn a second exception type."""


def _tool_version(plugin: Plugin, process_executor: ProcessExecutor) -> str | None:
    version_command = plugin.version_command()
    if version_command is None:
        return None
    try:
        result = process_executor.run(version_command, timeout=5)
    except OSError:
        return None
    if result.timed_out:
        return None
    return plugin.parse_version_output(result.stdout, result.stderr)


class ScanRunner:
    def __init__(
        self,
        policy: ScopePolicy,
        registry: PluginRegistry,
        store: EvidenceStore,
        audit: AuditStore | None = None,
        timeout: int = 300,
        concurrency: ConcurrencyGuard | None = None,
        process_executor: ProcessExecutor | None = None,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._store = store
        self._audit = audit
        self._timeout = timeout
        self._concurrency = concurrency
        self._process_executor = process_executor or ProcessExecutor()

    def run(
        self,
        target_name: str,
        plugin_name: str,
        options: dict[str, Any],
        on_line: OnLine | None = None,
    ) -> RunRecord:
        """Run PLUGIN_NAME against TARGET_NAME with OPTIONS -- the common
        case of "just run this plugin" outside any AttackOperation, which
        builds a bare ExecutionRequest (no action_id/approval_id) itself.
        A convenience wrapper around run_request(); see there for the
        general case."""
        request = ExecutionRequest(target=target_name, plugin=plugin_name, options=options)
        return self.run_request(request, on_line)

    def run_request(
        self,
        request: ExecutionRequest,
        on_line: OnLine | None = None,
    ) -> RunRecord:
        """Execute a fully-built ExecutionRequest, including one that
        carries action_id/approval_id because it represents an
        AttackOperation Action (core/operation/runner.py; refactor §18/P2
        §9) -- OperationRunner.execute() is the only caller that populates
        those two fields today."""
        target_name = request.target
        plugin_name = request.plugin
        try:
            target: Target = self._policy.authorize(target_name, plugin_name)
        except PolicyError as exc:
            if self._audit is not None:
                self._audit.record(target=target_name, plugin=plugin_name, reason=str(exc))
            raise

        try:
            if self._concurrency is None:
                return self._run_locked(target, request, on_line)
            with self._concurrency.acquire(target_name, target.max_concurrent):
                return self._run_locked(target, request, on_line)
        except (ConcurrencyError, ProcessLimitError) as exc:
            # ConcurrencyError (core/concurrency.py, cross-process, per-target
            # max_concurrent) and ProcessLimitError (core/process.py, refactor
            # v3 §8, in-process global concurrency / per-target cumulative
            # time budget) are two independent guards but the same "reject,
            # don't queue" story to the caller -- both surface as RunnerError
            # and get an AuditStore record the same way a scope violation does.
            if self._audit is not None:
                self._audit.record(target=target_name, plugin=plugin_name, reason=str(exc))
            raise RunnerError(str(exc)) from exc

    def _run_locked(
        self,
        target: Target,
        request: ExecutionRequest,
        on_line: OnLine | None,
    ) -> RunRecord:
        target_name = target.name
        plugin_name = request.plugin
        options = request.options
        plugin = self._registry.get(plugin_name)
        if not plugin.check():
            raise RunnerError(
                f"'{plugin.required_tool}' is required for the '{plugin_name}' plugin but "
                f"was not found on PATH. Install it, or run via the docker runtime image "
                f"(see docs/handbook.md #3) which already includes it."
            )

        plugin.validate_options(options)
        tool_version = _tool_version(plugin, self._process_executor)

        excluded_hosts: list[dict[str, str]] = []
        if plugin.host_list_option:
            options, excluded_hosts = self._resolve_host_list_option(plugin_name, plugin.host_list_option, options)

        # A fresh scratch directory per run -- see PluginExecution
        # (plugins/base.py). Two concurrent runs of this same shared Plugin
        # instance (PluginRegistry keeps one per name) each get their own
        # directory here, so a plugin's temp file (nmap -oX, ffuf -o, ...)
        # never collides with another run's.
        with tempfile.TemporaryDirectory(prefix=f"pownforge-{plugin_name}-") as workdir:
            execution = PluginExecution(Path(workdir))
            execution.data["excluded_hosts"] = excluded_hosts
            command = plugin.build_command(target, options, execution)

            process_result = self._process_executor.run(
                command, timeout=self._timeout, on_stdout_line=on_line, target_name=target_name
            )
            execution_result = execution_result_from_process(process_result)

            if execution_result.timed_out:
                record = self._save_timeout_record(
                    target_name, plugin_name, command, execution_result, tool_version
                )
                raise RunnerError(
                    f"plugin '{plugin_name}' timed out after {self._timeout}s "
                    f"(evidence saved as run '{record.run_id}')"
                )

            output = plugin.normalize(target, execution_result.stdout, execution_result.stderr, execution)
        # Convention: a plugin may pop-able-ly include an "_findings" key of
        # loosely-typed dicts (its own tool-native matches, not LLM output)
        # in the normalized output. ScanRunner turns those into real Finding
        # objects here; plugins that don't use this (network, web) are
        # unaffected and RunRecord.findings stays empty as before.
        raw_findings = output.pop("_findings", [])
        findings: list[Finding] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            finding = coerce_finding(item, source="tool")
            if finding is not None:
                findings.append(finding)

        evidence = Evidence(
            # Masked for storage/display only -- `command` (unmasked) is
            # what actually ran above, via subprocess.Popen.
            command=mask_command(command),
            started_at=execution_result.started_at,
            finished_at=execution_result.finished_at,
            returncode=execution_result.exit_code,
            stdout_sha256=sha256_text(execution_result.stdout),
            stderr_sha256=sha256_text(execution_result.stderr),
            tool_version=tool_version,
        )
        record = RunRecord(
            target=target_name,
            plugin=plugin_name,
            evidence=evidence,
            output=output,
            findings=findings,
        )
        self._store.save(record)
        return record

    def _save_timeout_record(
        self,
        target_name: str,
        plugin_name: str,
        command: list[str],
        execution_result: ExecutionResult,
        tool_version: str | None,
    ) -> RunRecord:
        """Persist a RunRecord for a timed-out run instead of discarding the
        evidence that the process DID run (refactor §16, a deliberate
        behavior change confirmed with the user -- PownForge previously
        raised RunnerError on timeout without ever calling
        EvidenceStore.save(), so the fact a scan ran was lost). `output`
        follows the same raw_stdout/raw_stderr convention every plugin's
        normalize() uses (see EvidenceStore.verify()), plus a `_timed_out`
        marker; `output` is a free-form dict, so this needs no schema
        change to Evidence/RunRecord. plugin.normalize() is deliberately
        not called here: it's written for complete tool output, and a
        killed process's partial stdout/stderr isn't a contract it
        promises to handle."""
        evidence = Evidence(
            command=mask_command(command),
            started_at=execution_result.started_at,
            finished_at=execution_result.finished_at,
            returncode=execution_result.exit_code,
            stdout_sha256=sha256_text(execution_result.stdout),
            stderr_sha256=sha256_text(execution_result.stderr),
            tool_version=tool_version,
        )
        record = RunRecord(
            target=target_name,
            plugin=plugin_name,
            evidence=evidence,
            output={
                "raw_stdout": execution_result.stdout,
                "raw_stderr": execution_result.stderr,
                "_timed_out": True,
            },
        )
        self._store.save(record)
        return record

    def _resolve_host_list_option(
        self, plugin_name: str, option_key: str, options: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, str]]]:
        """Authorize every name in options[option_key] (a comma-separated
        list of already-registered Target names -- see
        Plugin.host_list_option) the same way the primary target already
        was: ScopePolicy.authorize(), audited on denial. Returns a new
        options dict with the option replaced by the comma-separated
        *addresses* of only the names that passed, plus the list of
        excluded names+reasons (never silently dropped -- see
        plugin-additions §7.1 "範囲外のホストは、除外して記録する")."""
        raw_names = [n.strip() for n in str(options.get(option_key, "")).split(",") if n.strip()]
        accepted_addresses: list[str] = []
        excluded: list[dict[str, str]] = []
        for name in raw_names:
            try:
                secondary_target = self._policy.authorize(name, plugin_name)
            except PolicyError as exc:
                excluded.append({"name": name, "reason": str(exc)})
                if self._audit is not None:
                    self._audit.record(target=name, plugin=plugin_name, reason=str(exc))
                continue
            accepted_addresses.append(secondary_target.address)
        resolved_options = {**options, option_key: ",".join(accepted_addresses)}
        return resolved_options, excluded
