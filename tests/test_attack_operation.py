from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pownforge.core.models import Engagement, KillChainPhase, Target, TargetKind
from pownforge.core.operation import (
    Action,
    ActionKind,
    ActionStatus,
    AttackNodeState,
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


def test_execute_scan_action_forwards_on_line_callback(tmp_path: Path) -> None:
    """refactor v3 §1: OperationRunner.execute()'s on_line is how
    web/jobs.py streams a SCAN action's output live instead of blocking
    the request until the tool exits -- this pins that it actually
    reaches ScanRunner/ProcessExecutor for a real subprocess (echo)."""
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    lines: list[str] = []
    updated = _runner(tmp_path, _policy()).execute(operation, "a1", on_line=lines.append)

    action = next(a for a in updated.actions if a.id == "a1")
    assert action.status == ActionStatus.COMPLETED
    assert any("127.0.0.1" in line for line in lines)


def test_execute_success_moves_the_matching_node_to_succeeded(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    policy = _policy()
    add_node(store, policy, "op", "n-a", "a")
    add_action(
        store, policy, "op",
        Action(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")
    # add_action/approve_action never touch node state (refactor §12):
    # only an executed Action does.
    assert operation.nodes[0].state == AttackNodeState.KNOWN

    updated = _runner(tmp_path, policy).execute(operation, "a1")

    assert updated.nodes[0].state == AttackNodeState.SUCCEEDED


def test_execute_failure_moves_every_node_sharing_the_target_to_failed(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    # A policy that authorizes target "a" for scans in general (add_action
    # only checks the target is registered) but disallows the "network"
    # plugin specifically against it, so ScanRunner.authorize() raises
    # PolicyError once execute() actually runs it.
    policy = ScopePolicy(
        targets={"a": Target(name="a", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=["other-plugin"])}
    )
    # Two nodes registered against the same target -- both must move
    # together (refactor §12: node/action correspondence is by target,
    # and nothing prevents more than one node per target).
    add_node(store, policy, "op", "n-a1", "a", label="first view")
    add_node(store, policy, "op", "n-a2", "a", label="second view")
    add_action(
        store, policy, "op",
        Action(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    with pytest.raises(OperationError):
        _runner(tmp_path, policy).execute(operation, "a1")

    assert [n.state for n in operation.nodes] == [AttackNodeState.FAILED, AttackNodeState.FAILED]
    action = next(a for a in operation.actions if a.id == "a1")
    assert action.status == ActionStatus.REJECTED


def test_execute_rejects_action_with_unmet_requires(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(
            id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network",
            requires=["credential"],
        ),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    with pytest.raises(OperationError, match="requires"):
        _runner(tmp_path, _policy()).execute(operation, "a1")

    # Unmet requires is a distinct gate from approval/policy: the action
    # stays APPROVED, never COMPLETED and never REJECTED (refactor §13).
    action = next(a for a in operation.actions if a.id == "a1")
    assert action.status == ActionStatus.APPROVED


def test_execute_succeeds_once_a_prior_action_provides_the_required_tag(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(
            id="a0", name="get cred", phase=AttackPhase.CREDENTIAL_ACCESS, kind=ActionKind.SCAN,
            target="a", plugin="network", provides=["credential"],
        ),
    )
    add_action(
        store, _policy(), "op",
        Action(
            id="a1", name="use cred", phase=AttackPhase.LATERAL_MOVEMENT, kind=ActionKind.SCAN,
            target="a", plugin="network", requires=["credential"],
        ),
    )
    approve_action(store, "op", "a0", "operator")
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")

    runner = _runner(tmp_path, _policy())
    operation = runner.execute(operation, "a0")
    operation = runner.execute(operation, "a1")

    assert next(a for a in operation.actions if a.id == "a1").status == ActionStatus.COMPLETED


def test_execute_scan_action_links_the_approval_into_the_execution_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pownforge.core.models import ExecutionRequest
    from pownforge.core.runner import ScanRunner

    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_action(
        store, _policy(), "op",
        Action(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network"),
    )
    approve_action(store, "op", "a1", "operator")
    operation = store.load("op")
    approval_id = operation.approvals[0].id

    captured: list[ExecutionRequest] = []
    original = ScanRunner.run_request

    def spy(self, request, on_line=None):
        captured.append(request)
        return original(self, request, on_line)

    monkeypatch.setattr(ScanRunner, "run_request", spy)

    _runner(tmp_path, _policy()).execute(operation, "a1")

    assert len(captured) == 1
    assert captured[0].action_id == "a1"
    assert captured[0].approval_id == approval_id


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


def test_add_node_and_add_edge_accept_attack_technique_ids(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    policy = _policy()

    add_node(store, policy, "op", "n-a", "a", attack_technique_ids=["T1595"])
    add_node(store, policy, "op", "n-b", "b")
    add_edge(store, policy, "op", "a", "b", attack_technique_ids=["T1210"])

    operation = store.load("op")
    assert operation.nodes[0].attack_technique_ids == ["T1595"]
    assert operation.nodes[1].attack_technique_ids == []
    assert operation.edges[0].attack_technique_ids == ["T1210"]


def test_action_attack_technique_ids_defaults_to_empty_list() -> None:
    action = Action(id="a1", name="x", phase=AttackPhase.RECON, kind=ActionKind.SCAN, target="a", plugin="network")
    assert action.attack_technique_ids == []


def test_attack_operation_without_attack_technique_ids_loads_unchanged(tmp_path: Path) -> None:
    """Backward compatibility: a pre-existing operations/<name>.json with no
    attack_technique_ids field at all on its nodes/edges/actions must still
    load, defaulting to empty lists (refactor v3 §3/§12.5)."""
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")
    add_node(store, _policy(), "op", "n-a", "a")

    path = tmp_path / "operations" / "op.json"
    raw = json.loads(path.read_text())
    assert "attack_technique_ids" in raw["nodes"][0]  # sanity: current writer includes it
    del raw["nodes"][0]["attack_technique_ids"]
    path.write_text(json.dumps(raw))

    operation = store.load("op")
    assert operation.nodes[0].attack_technique_ids == []
