from __future__ import annotations

import subprocess
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from pownforge.core.concurrency import ConcurrencyError, ConcurrencyGuard
from pownforge.core.finding_utils import coerce_finding
from pownforge.core.models import Evidence, Finding, RunRecord, Target
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.secrets import mask_command
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.hashing import sha256_text
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin

OnLine = Callable[[str], None]


class RunnerError(RuntimeError):
    """Raised when a scan cannot be executed. Also raised (wrapping the
    original ConcurrencyError, see core/concurrency.py) when a target's
    max_concurrent limit is already reached -- callers that already catch
    RunnerError don't need to learn a second exception type."""


def _drain(stream, sink: list[str], on_line: OnLine | None) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)
        if on_line is not None:
            on_line(line.rstrip("\n"))
    stream.close()


def _tool_version(plugin: Plugin) -> str | None:
    version_command = plugin.version_command()
    if version_command is None:
        return None
    try:
        result = subprocess.run(version_command, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
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
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._store = store
        self._audit = audit
        self._timeout = timeout
        self._concurrency = concurrency

    def run(
        self,
        target_name: str,
        plugin_name: str,
        options: dict[str, Any],
        on_line: OnLine | None = None,
    ) -> RunRecord:
        try:
            target: Target = self._policy.authorize(target_name, plugin_name)
        except PolicyError as exc:
            if self._audit is not None:
                self._audit.record(target=target_name, plugin=plugin_name, reason=str(exc))
            raise

        if self._concurrency is None:
            return self._run_locked(target, plugin_name, options, on_line)
        try:
            with self._concurrency.acquire(target_name, target.max_concurrent):
                return self._run_locked(target, plugin_name, options, on_line)
        except ConcurrencyError as exc:
            if self._audit is not None:
                self._audit.record(target=target_name, plugin=plugin_name, reason=str(exc))
            raise RunnerError(str(exc)) from exc

    def _run_locked(
        self,
        target: Target,
        plugin_name: str,
        options: dict[str, Any],
        on_line: OnLine | None,
    ) -> RunRecord:
        target_name = target.name
        plugin = self._registry.get(plugin_name)
        if not plugin.check():
            raise RunnerError(
                f"'{plugin.required_tool}' is required for the '{plugin_name}' plugin but "
                f"was not found on PATH. Install it, or run via the docker runtime image "
                f"(see docs/handbook.md #3) which already includes it."
            )

        tool_version = _tool_version(plugin)

        command = plugin.build_command(target, options)
        started_at = datetime.now(timezone.utc)

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_lines, on_line))
        t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_lines, None))
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            t_out.join()
            t_err.join()
            raise RunnerError(f"plugin '{plugin_name}' timed out after {self._timeout}s")
        t_out.join()
        t_err.join()
        finished_at = datetime.now(timezone.utc)

        stdout_text = "".join(stdout_lines)
        stderr_text = "".join(stderr_lines)

        output = plugin.normalize(target, stdout_text, stderr_text)
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
            started_at=started_at,
            finished_at=finished_at,
            returncode=proc.returncode,
            stdout_sha256=sha256_text(stdout_text),
            stderr_sha256=sha256_text(stderr_text),
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
