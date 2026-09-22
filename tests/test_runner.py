from pathlib import Path
from typing import Any

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import ScanRunner
from pownforge.evidence.audit import AuditStore
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
    assert record.evidence.tool_version is None  # EchoPlugin doesn't override version_command

    store = EvidenceStore(tmp_path / "runs")
    reloaded = store.load(record.run_id)
    assert reloaded.run_id == record.run_id


class VersionedEchoPlugin(EchoPlugin):
    name = "versioned-echo"

    def version_command(self) -> list[str] | None:
        return ["echo", "FakeTool version 9.9.9"]


def test_runner_records_tool_version_when_plugin_supports_it(tmp_path: Path) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    registry = PluginRegistry()
    registry.register(VersionedEchoPlugin())
    store = EvidenceStore(tmp_path / "runs")
    runner = ScanRunner(policy=policy, registry=registry, store=store)

    record = runner.run("lab", "versioned-echo", {})

    assert record.evidence.tool_version == "FakeTool version 9.9.9"


def test_runner_rejects_unregistered_target(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path)
    with pytest.raises(PolicyError):
        runner.run("not-registered", "echo", {})


def test_runner_does_not_record_audit_when_none_given(tmp_path: Path) -> None:
    # audit is optional and defaults to off, so unit tests that don't care
    # about auditing (like the one above) don't need to wire one up.
    runner, _ = _runner(tmp_path)
    with pytest.raises(PolicyError):
        runner.run("not-registered", "echo", {})


def test_runner_records_policy_violation_to_audit_store(tmp_path: Path) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=["network"]))
    registry = PluginRegistry()
    registry.register(EchoPlugin())
    store = EvidenceStore(tmp_path / "runs")
    audit = AuditStore(tmp_path / "violations")
    runner = ScanRunner(policy=policy, registry=registry, store=store, audit=audit)

    with pytest.raises(PolicyError):
        runner.run("lab", "echo", {})

    violations = audit.list()
    assert len(violations) == 1
    assert violations[0].target == "lab"
    assert violations[0].plugin == "echo"
    assert "not authorized" in violations[0].reason


def test_runner_does_not_record_audit_on_successful_run(tmp_path: Path) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    registry = PluginRegistry()
    registry.register(EchoPlugin())
    store = EvidenceStore(tmp_path / "runs")
    audit = AuditStore(tmp_path / "violations")
    runner = ScanRunner(policy=policy, registry=registry, store=store, audit=audit)

    runner.run("lab", "echo", {})

    assert audit.list() == []


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


class FindingEmittingPlugin(Plugin):
    name = "findings-emitter"
    version = "0.0.1"
    description = "test double whose normalize() emits _findings"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [
                {"title": "Good finding", "severity": "high", "detail": "x"},
                {"title": "Bad severity", "severity": "not-a-real-severity", "detail": "y"},
                {"severity": "low", "detail": "no title, should be skipped"},
            ],
        }


def test_runner_converts_plugin_findings_convention(tmp_path: Path) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    registry = PluginRegistry()
    registry.register(FindingEmittingPlugin())
    store = EvidenceStore(tmp_path / "runs")
    runner = ScanRunner(policy=policy, registry=registry, store=store)

    record = runner.run("lab", "findings-emitter", {})

    assert len(record.findings) == 2
    assert record.findings[0].title == "Good finding"
    assert record.findings[0].severity.value == "high"
    assert record.findings[0].source == "tool"
    assert record.findings[0].status.value == "needs-review"
    assert record.findings[1].title == "Bad severity"
    assert record.findings[1].severity.value == "info"  # invalid severity falls back
    assert "_findings" not in record.output  # convention key is consumed, not stored raw
