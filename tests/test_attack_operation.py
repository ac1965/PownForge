from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pownforge.core.models import Engagement, KillChainPhase, Target, TargetKind
from pownforge.core.operation import (
    Action,
    ActionKind,
    ActionStatus,
    AttackPhase,
    AttackOperationStore,
    Capability,
    OperationError,
    OperationRunner,
    add_action,
    add_edge,
    add_node,
    approve_action,
    create_operation,
)
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginExecution


class EchoPlugin(Plugin):
    name = "network"
    version = "0.0.1"
    description = "test double standing in for the network plugin"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution) -> dict[str, Any]:
        return {"raw_stdout": raw_stdout, "raw_stderr": raw_stderr}


def _policy() -> ScopePolicy:
    return ScopePolicy(
        targets={
            "a": Target(name="a", kind=TargetKind.HOST, address="127.0.0.1"),
            "b": Target(name="b", kind=TargetKind.HOST, address="127.0.0.2"),
        }
    )


def test_operation_graph_and_approval(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op", objective="validate lab chain")
    policy = _policy()

    add_node(store, policy, "op", "n-a", "a", "source")
    add_node(store, policy, "op", "n-b", "b", "destination")
    add_edge(store, policy, "op", "a", "b", [Capability.NETWORK_PIVOT])
    action = Action(
        id="a1",
        name="network scan",
        phase=AttackPhase.RECON,
        kind=ActionKind.SCAN,
        target="a",
        plugin="network",
    )
    add_action(store, policy, "op", action)
    approve_action(store, "op", "a1", "operator", "authorized lab test")

    operation = store.load("op")
    assert operation.edges[0].source == "a"
    assert operation.actions[0].status == ActionStatus.APPROVED
    assert operation.approvals[0].approved_by == "operator"


def test_action_cannot_be_approved_twice_after_completion(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store,
        _policy(),
        "op",
        Action(
            id="a1",
            name="x",
            phase=AttackPhase.RECON,
            kind=ActionKind.SCAN,
            target="a",
            plugin="network",
        ),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")
    operation.actions[0].status = ActionStatus.COMPLETED
    store.save(operation)
    with pytest.raises(OperationError):
        approve_action(store, "op", "a1", "operator")


def _runner(tmp_path: Path, policy: ScopePolicy) -> OperationRunner:
    registry = PluginRegistry()
    registry.register(EchoPlugin())
    return OperationRunner(policy, registry, EvidenceStore(tmp_path / "runs"))


def test_execute_rejects_unapproved_action(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network"),
    )
    operation = store.load("op")
    with pytest.raises(OperationError, match="must be approved"):
        _runner(tmp_path, _policy()).execute(operation, "a1")


def test_execute_scan_action_runs_via_scanrunner(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    updated = _runner(tmp_path, _policy()).execute(operation, "a1")

    action = next(a for a in updated.actions if a.id == "a1")
    assert action.status == ActionStatus.COMPLETED
    assert action.run_id is not None


def test_execute_manual_action_requires_output(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="manual foothold", phase=AttackPhase.INITIAL_ACCESS, kind=ActionKind.MANUAL, target="a"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    with pytest.raises(OperationError, match="requires --output"):
        _runner(tmp_path, _policy()).execute(operation, "a1")


def test_execute_manual_action_records_evidence_without_a_plugin(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="manual foothold", phase=AttackPhase.INITIAL_ACCESS, kind=ActionKind.MANUAL, target="a"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    updated = _runner(tmp_path, _policy()).execute(
        operation, "a1", manual_command="msfconsole exploit/...", manual_output="uid=0(root)", manual_tool="msfconsole"
    )

    action = next(a for a in updated.actions if a.id == "a1")
    assert action.status == ActionStatus.COMPLETED
    assert action.run_id is not None


def test_execute_pivot_action_requires_engagement(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")  # no --engagement
    policy = _policy()
    add_node(store, policy, "op", "n-a", "a")
    add_node(store, policy, "op", "n-b", "b")
    add_edge(store, policy, "op", "a", "b")
    add_action(
        store, policy, "op",
        Action(id="a1", name="pivot", phase=AttackPhase.LATERAL_MOVEMENT, kind=ActionKind.PIVOT, target="b"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    with pytest.raises(OperationError, match="requires the operation to have an engagement"):
        _runner(tmp_path, policy).execute(operation, "a1", manual_output="session opened")


def test_execute_pivot_action_requires_a_graph_edge(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op", engagement="eng")
    policy = _policy()
    policy.add_engagement(Engagement(name="eng", targets=["a", "b"]))
    add_node(store, policy, "op", "n-a", "a")
    add_node(store, policy, "op", "n-b", "b")
    # no add_edge()
    add_action(
        store, policy, "op",
        Action(id="a1", name="pivot", phase=AttackPhase.LATERAL_MOVEMENT, kind=ActionKind.PIVOT, target="b"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    with pytest.raises(OperationError, match="no graph edge"):
        _runner(tmp_path, policy).execute(operation, "a1", manual_output="session opened")


def test_execute_pivot_action_records_via_target_and_engagement(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op", engagement="eng")
    policy = _policy()
    policy.add_engagement(Engagement(name="eng", targets=["a", "b"]))
    add_node(store, policy, "op", "n-a", "a")
    add_node(store, policy, "op", "n-b", "b")
    add_edge(store, policy, "op", "a", "b")
    add_action(
        store, policy, "op",
        Action(id="a1", name="pivot", phase=AttackPhase.LATERAL_MOVEMENT, kind=ActionKind.PIVOT, target="b"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")
    evidence = EvidenceStore(tmp_path / "runs")
    runner = OperationRunner(policy, PluginRegistry(), evidence)

    updated = runner.execute(operation, "a1", manual_output="svcuser@b:~$", manual_command="ssh b")

    action = next(a for a in updated.actions if a.id == "a1")
    record = evidence.load(action.run_id)
    assert record.via_target == "a"
    assert record.engagement == "eng"
    assert record.kill_chain_phase == KillChainPhase.LATERAL_MOVEMENT


def test_execute_maps_attack_phase_to_kill_chain_phase(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="manual", phase=AttackPhase.PERSISTENCE, kind=ActionKind.MANUAL, target="a"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")
    evidence = EvidenceStore(tmp_path / "runs")
    runner = OperationRunner(_policy(), PluginRegistry(), evidence)

    updated = runner.execute(operation, "a1", manual_output="cron job installed")

    action = next(a for a in updated.actions if a.id == "a1")
    record = evidence.load(action.run_id)
    assert record.kill_chain_phase == KillChainPhase.PERSISTENCE


def test_execute_leaves_kill_chain_phase_unset_for_phases_without_a_mapping(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="manual", phase=AttackPhase.CREDENTIAL_ACCESS, kind=ActionKind.MANUAL, target="a"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")
    evidence = EvidenceStore(tmp_path / "runs")
    runner = OperationRunner(_policy(), PluginRegistry(), evidence)

    updated = runner.execute(operation, "a1", manual_output="dumped credentials")

    action = next(a for a in updated.actions if a.id == "a1")
    record = evidence.load(action.run_id)
    assert record.kill_chain_phase is None
