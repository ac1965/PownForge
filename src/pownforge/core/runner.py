from __future__ import annotations

import subprocess
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from pownforge.core.models import Evidence, RunRecord, Target
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.hashing import sha256_text
from pownforge.evidence.store import EvidenceStore

OnLine = Callable[[str], None]


class RunnerError(RuntimeError):
    """Raised when a scan cannot be executed."""


def _drain(stream, sink: list[str], on_line: OnLine | None) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)
        if on_line is not None:
            on_line(line.rstrip("\n"))
    stream.close()


class ScanRunner:
    def __init__(
        self,
        policy: ScopePolicy,
        registry: PluginRegistry,
        store: EvidenceStore,
        audit: AuditStore | None = None,
        timeout: int = 300,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._store = store
        self._audit = audit
        self._timeout = timeout

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
        plugin = self._registry.get(plugin_name)
        if not plugin.check():
            raise RunnerError(
                f"'{plugin.required_tool}' is required for the '{plugin_name}' plugin but "
                f"was not found on PATH. Install it, or run via the docker runtime image "
                f"(see docs/lab.md) which already includes it."
            )

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
        evidence = Evidence(
            command=command,
            started_at=started_at,
            finished_at=finished_at,
            returncode=proc.returncode,
            stdout_sha256=sha256_text(stdout_text),
            stderr_sha256=sha256_text(stderr_text),
        )
        record = RunRecord(
            target=target_name,
            plugin=plugin_name,
            evidence=evidence,
            output=output,
        )
        self._store.save(record)
        return record
