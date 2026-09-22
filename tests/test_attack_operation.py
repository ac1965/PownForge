from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.core.operation import (
    Action,
    ActionKind,
    ActionStatus,
    AttackPhase,
    AttackOperationStore,
    Capability,
    OperationError,
    add_action,
    add_edge,
    add_node,
    approve_action,
    create_operation,
)
from pownforge.core.policy import ScopePolicy


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
