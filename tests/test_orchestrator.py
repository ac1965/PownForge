from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pownforge.core.models import (
    Finding,
    Playbook,
    PlaybookStep,
    PlaybookStepCondition,
    Severity,
    Target,
    TargetKind,
)
from pownforge.core.orchestrator import (
    PlaybookError,
    list_playbooks,
    load_playbook,
    resolve_playbook,
    run_playbook,
)
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginError


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


class FindingPlugin(Plugin):
    """Test double whose normalize() reports one finding at a configurable
    severity (via options["severity"]), through the same "_findings"
    convention a real plugin (e.g. nuclei) uses."""

    name = "finding-maker"
    version = "0.0.1"
    description = "test double that reports one finding at options['severity']"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        return ["echo", options.get("severity", "info")]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [{"title": "simulated finding", "severity": raw_stdout.strip(), "detail": ""}],
        }


class AlwaysFailsPlugin(Plugin):
    name = "always-fails"
    version = "0.0.1"
    description = "test double whose build_command always raises"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        raise PluginError("simulated failure")

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {}


def _setup(tmp_path: Path) -> tuple[ScopePolicy, PluginRegistry, EvidenceStore]:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    registry = PluginRegistry()
    registry.register(EchoPlugin())
    registry.register(AlwaysFailsPlugin())
    registry.register(FindingPlugin())
    store = EvidenceStore(tmp_path / "runs")
    return policy, registry, store


def test_run_playbook_executes_every_step_in_order(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    playbook = Playbook(
        name="two-echoes",
        steps=[PlaybookStep(plugin="echo", options={}), PlaybookStep(plugin="echo", options={})],
    )

    results = run_playbook(playbook, "lab", policy, registry, store)

    assert len(results) == 2
    assert all(r.record is not None and r.error is None for r in results)
    assert results[0].record.run_id != results[1].record.run_id


def test_run_playbook_continues_after_a_failing_step(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    playbook = Playbook(
        name="fail-then-succeed",
        steps=[
            PlaybookStep(plugin="always-fails", options={}),
            PlaybookStep(plugin="echo", options={}),
        ],
    )

    results = run_playbook(playbook, "lab", policy, registry, store)

    assert len(results) == 2
    assert results[0].record is None
    assert "simulated failure" in results[0].error
    assert results[1].record is not None
    assert results[1].error is None


def test_run_playbook_reports_policy_rejection_without_stopping(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    # "echo" isn't in this target's allowed_plugins.
    policy.add_target(Target(name="locked", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=["other"]))
    playbook = Playbook(name="p", steps=[PlaybookStep(plugin="echo", options={})])

    results = run_playbook(playbook, "locked", policy, registry, store)

    assert results[0].record is None
    assert "not authorized" in results[0].error


def test_run_playbook_calls_on_step_callback_with_index_and_total(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    playbook = Playbook(
        name="p", steps=[PlaybookStep(plugin="echo", options={}), PlaybookStep(plugin="echo", options={})]
    )
    seen: list[tuple[int, int, str]] = []

    run_playbook(
        playbook,
        "lab",
        policy,
        registry,
        store,
        on_step=lambda i, total, step: seen.append((i, total, step.plugin)),
    )

    assert seen == [(1, 2, "echo"), (2, 2, "echo")]


def test_run_playbook_runs_gated_step_when_severity_threshold_met(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    playbook = Playbook(
        name="p",
        steps=[
            PlaybookStep(plugin="finding-maker", options={"severity": "high"}),
            PlaybookStep(
                plugin="echo", when=PlaybookStepCondition(after_step=1, min_severity=Severity.MEDIUM)
            ),
        ],
    )

    results = run_playbook(playbook, "lab", policy, registry, store)

    assert results[0].record.findings[0].severity == Severity.HIGH
    assert results[1].skipped is False
    assert results[1].record is not None


def test_run_playbook_skips_gated_step_when_severity_threshold_not_met(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    playbook = Playbook(
        name="p",
        steps=[
            PlaybookStep(plugin="finding-maker", options={"severity": "low"}),
            PlaybookStep(
                plugin="echo", when=PlaybookStepCondition(after_step=1, min_severity=Severity.HIGH)
            ),
        ],
    )

    results = run_playbook(playbook, "lab", policy, registry, store)

    assert results[1].skipped is True
    assert results[1].record is None
    assert results[1].error is None


def test_run_playbook_skips_gated_step_when_gate_step_failed(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    playbook = Playbook(
        name="p",
        steps=[
            PlaybookStep(plugin="always-fails", options={}),
            PlaybookStep(
                plugin="echo", when=PlaybookStepCondition(after_step=1, min_severity=Severity.INFO)
            ),
        ],
    )

    results = run_playbook(playbook, "lab", policy, registry, store)

    assert results[0].record is None  # failed
    assert results[1].skipped is True  # a failed gate step never satisfies a condition


def test_run_playbook_rejects_when_referencing_a_later_or_equal_step(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    # Step 1 tries to gate on itself.
    playbook = Playbook(
        name="p",
        steps=[
            PlaybookStep(plugin="echo", when=PlaybookStepCondition(after_step=1, min_severity=Severity.INFO)),
        ],
    )
    with pytest.raises(PlaybookError):
        run_playbook(playbook, "lab", policy, registry, store)


def test_run_playbook_rejects_when_referencing_step_zero(tmp_path: Path) -> None:
    policy, registry, store = _setup(tmp_path)
    playbook = Playbook(
        name="p",
        steps=[
            PlaybookStep(plugin="echo", options={}),
            PlaybookStep(plugin="echo", when=PlaybookStepCondition(after_step=0, min_severity=Severity.INFO)),
        ],
    )
    with pytest.raises(PlaybookError):
        run_playbook(playbook, "lab", policy, registry, store)


def test_load_playbook_parses_yaml(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(
        "name: p\ndescription: test playbook\nsteps:\n"
        "  - plugin: network\n    options:\n      ports: '80'\n  - plugin: web\n"
    )

    playbook = load_playbook(path)

    assert playbook.name == "p"
    assert playbook.description == "test playbook"
    assert len(playbook.steps) == 2
    assert playbook.steps[0].plugin == "network"
    assert playbook.steps[0].options == {"ports": "80"}
    assert playbook.steps[1].options == {}
    assert playbook.steps[0].when is None


def test_load_playbook_parses_when_condition(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(
        "name: p\nsteps:\n"
        "  - plugin: nuclei\n"
        "  - plugin: sqlmap\n    when:\n      after_step: 1\n      min_severity: high\n"
    )

    playbook = load_playbook(path)

    assert playbook.steps[1].when == PlaybookStepCondition(after_step=1, min_severity=Severity.HIGH)


def test_load_playbook_raises_for_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("not_a_valid_field: true\n")
    with pytest.raises(PlaybookError):
        load_playbook(path)


def test_resolve_playbook_raises_for_unknown_name(tmp_path: Path) -> None:
    with pytest.raises(PlaybookError):
        resolve_playbook(tmp_path, "does-not-exist")


def test_resolve_playbook_finds_by_filename_stem(tmp_path: Path) -> None:
    (tmp_path / "web-baseline.yaml").write_text("name: web-baseline\nsteps: []\n")
    playbook = resolve_playbook(tmp_path, "web-baseline")
    assert playbook.name == "web-baseline"


def test_list_playbooks_returns_empty_for_missing_dir(tmp_path: Path) -> None:
    assert list_playbooks(tmp_path / "does-not-exist") == []


def test_list_playbooks_sorted_by_name(tmp_path: Path) -> None:
    (tmp_path / "b.yaml").write_text("name: b-playbook\nsteps: []\n")
    (tmp_path / "a.yaml").write_text("name: a-playbook\nsteps: []\n")

    playbooks = list_playbooks(tmp_path)

    assert [p.name for p in playbooks] == ["a-playbook", "b-playbook"]


def test_real_web_baseline_playbook_file_loads() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    playbook = load_playbook(repo_root / "config" / "playbooks" / "web-baseline.yaml")
    assert playbook.name == "web-baseline"
    assert [s.plugin for s in playbook.steps] == ["network", "web", "nuclei"]
