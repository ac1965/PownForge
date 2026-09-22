from pathlib import Path
from typing import Any

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import ScanRunner
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin


class EchoPlugin(Plugin):
    name = "echo"
    version = "0.0.1"
    description = "test double that just echoes the target address"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {"raw_stdout": raw_stdout, "raw_stderr": raw_stderr}


def _runner(tmp_path: Path) -> tuple[ScanRunner, ScopePolicy]:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    registry = PluginRegistry()
    registry.register(EchoPlugin())
    store = EvidenceStore(tmp_path / "runs")
    return ScanRunner(policy=policy, registry=registry, store=store), policy


def test_runner_executes_and_persists(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path)
    record = runner.run("lab", "echo", {})

    assert record.evidence.returncode == 0
    assert "127.0.0.1" in record.output["raw_stdout"]

    store = EvidenceStore(tmp_path / "runs")
    reloaded = store.load(record.run_id)
    assert reloaded.run_id == record.run_id


def test_runner_rejects_unregistered_target(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path)
    with pytest.raises(PolicyError):
        runner.run("not-registered", "echo", {})


class MultiLinePlugin(Plugin):
    name = "multiline"
    version = "0.0.1"
    description = "test double that prints several lines"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        return ["sh", "-c", "printf 'a\\nb\\nc\\n'"]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {"raw_stdout": raw_stdout, "raw_stderr": raw_stderr}


def test_runner_streams_lines_via_on_line_callback(tmp_path: Path) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    registry = PluginRegistry()
    registry.register(MultiLinePlugin())
    store = EvidenceStore(tmp_path / "runs")
    runner = ScanRunner(policy=policy, registry=registry, store=store)

    seen: list[str] = []
    record = runner.run("lab", "multiline", {}, on_line=seen.append)

    assert seen == ["a", "b", "c"]
    assert record.output["raw_stdout"] == "a\nb\nc\n"
    assert record.evidence.returncode == 0
