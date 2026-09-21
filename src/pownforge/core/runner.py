from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from typing import Any

from pownforge.core.models import Evidence, RunRecord, Target
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.evidence.hashing import sha256_text
from pownforge.evidence.store import EvidenceStore


class RunnerError(RuntimeError):
    """Raised when a scan cannot be executed."""


class ScanRunner:
    def __init__(
        self,
        policy: ScopePolicy,
        registry: PluginRegistry,
        store: EvidenceStore,
        timeout: int = 300,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._store = store
        self._timeout = timeout

    def run(self, target_name: str, plugin_name: str, options: dict[str, Any]) -> RunRecord:
        target: Target = self._policy.authorize(target_name, plugin_name)
        plugin = self._registry.get(plugin_name)
        if not plugin.check():
            raise RunnerError(f"required tool for plugin '{plugin_name}' is not available")

        command = plugin.build_command(target, options)
        started_at = datetime.now(timezone.utc)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"plugin '{plugin_name}' timed out after {self._timeout}s") from exc
        finished_at = datetime.now(timezone.utc)

        output = plugin.normalize(target, completed.stdout, completed.stderr)
        evidence = Evidence(
            command=command,
            started_at=started_at,
            finished_at=finished_at,
            returncode=completed.returncode,
            stdout_sha256=sha256_text(completed.stdout),
            stderr_sha256=sha256_text(completed.stderr),
        )
        record = RunRecord(
            target=target_name,
            plugin=plugin_name,
            evidence=evidence,
            output=output,
        )
        self._store.save(record)
        return record
