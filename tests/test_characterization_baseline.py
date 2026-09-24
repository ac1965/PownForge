"""Phase 0 baseline characterization tests for the Security Assessment
Orchestrator refactor (see the refactoring instructions this session was
given, section 1: 不変条件 / invariants, and section 3.2: フェーズ0の
特性テスト).

These tests fix two kinds of facts about the CURRENT codebase, before any
responsibility is moved around in later phases:

1. The public import paths third parties (tests, CLI, web, emacs) rely on
   today, so splitting operation.py / models.py in P1 can be verified not
   to break them (a Facade must keep these importable).
2. The safety invariants in AGENTS.md and the refactor instructions (scope
   validation cannot be bypassed, execution requires approval, manual/pivot
   actions never invoke an external tool themselves, plugin denylists stay
   effective, the AI adapter has no import path into the execution layer).

None of these tests should ever need to become *more* permissive as the
refactor proceeds -- if a later phase would break one, that phase's design
is wrong, not the test (see 不変条件, which the instructions rank above
"but it's cleaner this way").
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.core.operation import (
    Action,
    ActionKind,
    ActionStatus,
    AttackOperationStore,
    AttackPhase,
    Capability,
    OperationError,
    OperationRunner,
    add_action,
    add_edge,
    add_node,
    approve_action,
    create_operation,
)
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import default_registry
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginExecution
from pownforge.plugins.sqlmap import _DENIED_OPTIONS, SqlmapPlugin
from pownforge.plugins.vulncheck import _ALLOWED_SCRIPTS, VulncheckPlugin


# ---------------------------------------------------------------------------
# 1. Facade import stability (§3.2)
# ---------------------------------------------------------------------------


def test_core_models_facade_imports() -> None:
    """The import paths existing callers (tests/, cli.py, web/, emacs) use
    today. If models.py is later split into core/models/*.py, a Facade
    package must keep every one of these importable from this exact path."""
    from pownforge.core.models import (  # noqa: F401
        Artifact,
        AttackSession,
        AttackSessionStage,
        Capability,
        Claim,
        Engagement,
        Evidence,
        EvidenceVerification,
        ExecutionRequest,
        ExecutionResult,
        ExecutionStatus,
        Finding,
        FindingStatus,
        HashCheck,
        KillChainPhase,
        Playbook,
        PlaybookStep,
        PlaybookStepCondition,
        PluginMetadata,
        PluginOption,
        PolicyViolation,
        Precondition,
        PreconditionReport,
        PrimitiveDescriptor,
        PrimitiveRunRecord,
        Provenance,
        RunRecord,
        SafetyPolicy,
        Severity,
        Suggestion,
        Target,
        TargetEnvironment,
        TargetKind,
        TargetType,
        ValidationLevel,
    )


def test_core_operation_facade_imports() -> None:
    """The import paths for the Attack Graph / Operation model. If
    operation.py is split in P1 (AttackGraph extraction), a Facade must
    keep these importable from `pownforge.core.operation`."""
    from pownforge.core.operation import (  # noqa: F401
        Action,
        ActionKind,
        ActionStatus,
        Approval,
        AttackEdge,
        AttackNode,
        AttackOperation,
        AttackOperationStore,
        AttackPhase,
        OperationError,
        OperationRunner,
        PrimitiveContext,
        PrimitiveRunner,
        ValidationPrimitive,
        add_action,
        add_edge,
        add_node,
        approve_action,
        create_operation,
    )


def test_core_policy_facade_imports() -> None:
    from pownforge.core.policy import PolicyError, SafetyError, ScopePolicy  # noqa: F401


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


class _EchoPlugin(Plugin):
    """Stands in for the real 'network' plugin so tests don't depend on nmap
    being installed. Deliberately never touches self._* state, unlike some
    real plugins (see P0 investigation notes) -- that's orthogonal to what
    this file characterizes."""

    name = "network"
    version = "0.0.1"
    description = "test double"
    required_tool = "echo"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution) -> dict[str, Any]:
        return {"raw_stdout": raw_stdout, "raw_stderr": raw_stderr}


def _scoped_policy() -> ScopePolicy:
    return ScopePolicy(
        targets={"a": Target(name="a", kind=TargetKind.HOST, address="127.0.0.1")}
    )


def _operation_env(tmp_path: Path):
    policy = _scoped_policy()
    store = AttackOperationStore(tmp_path / "operations")
    registry = default_registry()
    registry.register(_EchoPlugin())  # shadow the real 'network' plugin
    evidence = EvidenceStore(tmp_path / "runs")
    runner = OperationRunner(policy=policy, registry=registry, store=evidence)
    create_operation(store, "op")
    add_node(store, policy, "op", "n1", "a")
    return policy, store, registry, evidence, runner


# ---------------------------------------------------------------------------
# 2. §1.1 Scope validation cannot be bypassed
# ---------------------------------------------------------------------------


def test_scan_runner_rejects_unregistered_target(tmp_path: Path) -> None:
    from pownforge.core.runner import ScanRunner

    policy = ScopePolicy(targets={})
    audit = AuditStore(tmp_path / "violations")
    runner = ScanRunner(
        policy=policy,
        registry=default_registry(),
        store=EvidenceStore(tmp_path / "runs"),
        audit=audit,
    )
    with pytest.raises(PolicyError):
        runner.run("not-a-target", "network", {})
    # AGENTS.md: a denied attempt must always be recorded, never silently
    # swallowed.
    violations = audit.list()
    assert len(violations) == 1
    assert violations[0].target == "not-a-target"


def test_add_node_rejects_unregistered_target(tmp_path: Path) -> None:
    """The Attack Graph entry point re-checks scope itself -- it must not
    rely solely on the eventual ScanRunner call to catch an out-of-scope
    target."""
    policy = ScopePolicy(targets={})
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    with pytest.raises(PolicyError):
        add_node(store, policy, "op", "n1", "not-a-target")


def test_add_action_rejects_unregistered_target(tmp_path: Path) -> None:
    policy, store, registry, evidence, _runner = _operation_env(tmp_path)
    with pytest.raises(PolicyError):
        add_action(
            store,
            policy,
            "op",
            Action(
                id="act1",
                name="scan",
                phase=AttackPhase.RECON,
                kind=ActionKind.SCAN,
                target="not-a-target",
                plugin="network",
            ),
        )


# ---------------------------------------------------------------------------
# 3. §1.2 Execution requires approval; manual/pivot never run a subprocess
# ---------------------------------------------------------------------------


def test_execute_rejects_an_action_that_was_never_approved(tmp_path: Path) -> None:
    policy, store, registry, evidence, runner = _operation_env(tmp_path)
    add_action(
        store,
        policy,
        "op",
        Action(id="a1", name="scan", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network"),
    )
    operation = store.load("op")
    with pytest.raises(OperationError):
        runner.execute(operation, "a1")


def test_manual_action_completes_without_ever_invoking_a_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Current, intended behaviour (confirmed with the user during Phase 0):
    manual/pivot actions are NOT unconditionally rejected by execute() --
    they complete when a human already produced the evidence externally
    (--output), and PownForge itself never runs a command for them. The
    invariant is 'no execution provider is enabled for manual/pivot', not
    'execute always raises'."""
    import subprocess as subprocess_module

    def _forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("manual action execute() must never spawn a subprocess")

    monkeypatch.setattr(subprocess_module, "Popen", _forbidden)
    monkeypatch.setattr(subprocess_module, "run", _forbidden)

    policy, store, registry, evidence, runner = _operation_env(tmp_path)
    add_action(
        store,
        policy,
        "op",
        Action(id="m1", name="manual exploit", phase=AttackPhase.INITIAL_ACCESS, kind=ActionKind.MANUAL, target="a"),
    )
    approve_action(store, "op", "m1", approved_by="tester")
    operation = store.load("op")

    result = runner.execute(operation, "m1", manual_output="human-produced transcript")

    action = next(a for a in result.actions if a.id == "m1")
    assert action.status == ActionStatus.COMPLETED
    assert action.run_id is not None


def test_manual_action_execute_without_output_is_rejected(tmp_path: Path) -> None:
    """The one case execute() DOES reject for manual/pivot: no external
    evidence was supplied. This is the actual (narrower) rejection rule --
    not "always reject" as an earlier draft of the invariant assumed."""
    policy, store, registry, evidence, runner = _operation_env(tmp_path)
    add_action(
        store,
        policy,
        "op",
        Action(id="m1", name="manual exploit", phase=AttackPhase.INITIAL_ACCESS, kind=ActionKind.MANUAL, target="a"),
    )
    approve_action(store, "op", "m1", approved_by="tester")
    operation = store.load("op")
    with pytest.raises(OperationError):
        runner.execute(operation, "m1")


def test_pivot_action_completes_without_ever_invoking_a_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pownforge.core.models import Engagement

    import subprocess as subprocess_module

    def _forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("pivot action execute() must never spawn a subprocess")

    monkeypatch.setattr(subprocess_module, "Popen", _forbidden)
    monkeypatch.setattr(subprocess_module, "run", _forbidden)

    policy = ScopePolicy(
        targets={
            "a": Target(name="a", kind=TargetKind.HOST, address="127.0.0.1"),
            "b": Target(name="b", kind=TargetKind.HOST, address="127.0.0.2"),
        }
    )
    policy.add_engagement(Engagement(name="eng", targets=["a", "b"]))
    store = AttackOperationStore(tmp_path / "operations")
    registry = default_registry()
    evidence = EvidenceStore(tmp_path / "runs")
    runner = OperationRunner(policy=policy, registry=registry, store=evidence)
    create_operation(store, "op", engagement="eng")
    add_node(store, policy, "op", "n1", "a")
    add_node(store, policy, "op", "n2", "b")
    add_edge(store, policy, "op", "a", "b")
    add_action(
        store,
        policy,
        "op",
        Action(id="p1", name="pivot to b", phase=AttackPhase.LATERAL_MOVEMENT, kind=ActionKind.PIVOT, target="b"),
    )
    approve_action(store, "op", "p1", approved_by="tester")
    operation = store.load("op")

    result = runner.execute(operation, "p1", manual_output="human-produced transcript")

    action = next(a for a in result.actions if a.id == "p1")
    assert action.status == ActionStatus.COMPLETED


# ---------------------------------------------------------------------------
# 4. §1.3 Plugin denylists stay effective
# ---------------------------------------------------------------------------


def test_vulncheck_allowlist_is_exactly_the_baseline_15_scripts() -> None:
    """Locks the allowlist size so a future refactor can't silently grow or
    shrink it. If this test needs to change, that's a deliberate scope
    decision, not a refactor side effect."""
    assert len(_ALLOWED_SCRIPTS) == 15


def test_vulncheck_rejects_a_script_outside_the_allowlist(tmp_path: Path) -> None:
    plugin = VulncheckPlugin()
    target = Target(name="a", kind=TargetKind.HOST, address="127.0.0.1")
    from pownforge.plugins.base import PluginError

    with pytest.raises(PluginError):
        plugin.build_command(
            target, {"script": "smb-vuln-ms08-067"}, PluginExecution(tmp_path)
        )  # exploit-class, not on the list


def test_sqlmap_denylist_still_blocks_os_and_file_options() -> None:
    for option in ("os-shell", "os-pwn", "file-read", "file-write", "reg-add", "tamper"):
        assert option in _DENIED_OPTIONS


def test_sqlmap_rejects_a_denied_option_regardless_of_risk_level(tmp_path: Path) -> None:
    from pownforge.plugins.base import PluginError

    plugin = SqlmapPlugin()
    target = Target(name="a", kind=TargetKind.URL, address="http://127.0.0.1/?id=1")
    with pytest.raises(PluginError):
        plugin.build_command(target, {"os-shell": "true", "risk": "3", "level": "5"}, PluginExecution(tmp_path))


# ---------------------------------------------------------------------------
# 5. §1.4 AI has no import path into the execution layer
# ---------------------------------------------------------------------------

_EXECUTION_MODULES = {"runner", "operation", "policy", "lab", "concurrency"}


def test_ai_adapter_does_not_import_the_execution_layer() -> None:
    """Static check: no file under src/pownforge/ai/ imports
    core.runner / core.operation / core.policy / core.lab / core.concurrency.
    A green result here means there is currently no code path for an LLM
    adapter to reach ScanRunner, OperationRunner, ScopePolicy or LabManager
    -- the AI/execution boundary the refactor must keep intact."""
    ai_dir = Path(__file__).resolve().parents[1] / "src" / "pownforge" / "ai"
    assert ai_dir.is_dir()
    offending: list[str] = []
    for path in sorted(ai_dir.glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
            if module is None:
                continue
            parts = module.split(".")
            if "core" in parts:
                idx = parts.index("core")
                if idx + 1 < len(parts) and parts[idx + 1] in _EXECUTION_MODULES:
                    offending.append(f"{path.name}: {module}")
    assert offending == [], f"AI adapter imports the execution layer: {offending}"
