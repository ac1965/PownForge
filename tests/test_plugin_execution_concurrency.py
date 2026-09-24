"""P0 §4.1 required test: the SAME Plugin instance, used for two concurrent
Target runs, must not mix up its temp paths or output. Before PluginExecution
existed, plugins stashed a temp path on `self` between build_command() and
normalize() (self._xml_path and friends) -- since PluginRegistry keeps one
Plugin instance per name shared across every run (core/registry.py), two
concurrent ScanRunner.run() calls against the same plugin name (e.g. two
Web UI requests scanning different targets with 'network' at once) could
clobber each other's path. This test drives that exact scenario through the
real ScanRunner/PluginRegistry/ProcessExecutor path -- not a unit-level
call -- so it actually exercises the shared-instance race."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import ScanRunner
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginExecution


class _SlowFileWritingPlugin(Plugin):
    """Writes the target's own address into its execution-scoped temp file,
    with an artificial delay between the write (in build_command, i.e.
    before the "tool" runs) and the read (in normalize, i.e. after) -- wide
    enough that two concurrent runs are certain to overlap. If execution
    state were ever shared (the old self._x pattern under a shared
    instance), one run's read would see the other run's write."""

    name = "slow-file"
    version = "0.0.1"
    description = "test double for the P0 concurrency requirement"
    required_tool = "true"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        marker = execution.path("marker.txt")
        marker.write_text(target.address)
        # The "tool" itself just sleeps -- ScanRunner's ProcessExecutor runs
        # this for real, so the delay is between two concurrent threads'
        # build_command()/normalize() calls, exactly where the old
        # self._x-based race would bite.
        return ["sh", "-c", "sleep 0.2"]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        marker = execution.path("marker.txt")
        return {"target": target.address, "marker_contents": marker.read_text()}


def test_same_plugin_instance_concurrent_runs_do_not_mix_temp_paths(tmp_path: Path) -> None:
    plugin = _SlowFileWritingPlugin()  # ONE shared instance, like the registry gives ScanRunner
    registry = PluginRegistry()
    registry.register(plugin)

    policy = ScopePolicy(
        targets={
            "a": Target(name="a", kind=TargetKind.HOST, address="target-a-address"),
            "b": Target(name="b", kind=TargetKind.HOST, address="target-b-address"),
        }
    )
    store = EvidenceStore(tmp_path / "runs")
    runner = ScanRunner(policy=policy, registry=registry, store=store, timeout=5)

    results: dict[str, Any] = {}
    errors: list[BaseException] = []

    def run(target_name: str) -> None:
        try:
            record = runner.run(target_name, "slow-file", {})
            results[target_name] = record.output
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(name,)) for name in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent runs raised: {errors}"
    assert results["a"]["marker_contents"] == "target-a-address"
    assert results["b"]["marker_contents"] == "target-b-address"
