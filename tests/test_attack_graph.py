"""P1 §5.3/§5.3.1: AttackGraph extraction and AttackNode.state typing.

Both changes are deliberately code-level only -- the persisted AttackOperation
JSON schema (top-level "nodes"/"edges" keys, "state": "known" default) is
unchanged, so every AttackOperation already on disk keeps loading exactly as
before (see AttackGraph's docstring and AttackNodeState's docstring)."""

from __future__ import annotations

from pathlib import Path

from pownforge.core.operation import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackNodeState,
    AttackOperation,
    AttackOperationStore,
    Capability,
    attack_graph,
)


def test_attack_graph_queries() -> None:
    graph = AttackGraph(
        nodes=[AttackNode(id="n1", target="a"), AttackNode(id="n2", target="b")],
        edges=[AttackEdge(source="a", destination="b", capabilities=[Capability.NETWORK_PIVOT])],
    )
    assert graph.node("n1").target == "a"
    assert graph.node("missing") is None
    assert graph.has_target("a") is True
    assert graph.has_target("c") is False
    assert graph.neighbors("a") == ["b"]
    assert [e.source for e in graph.incoming_edges("b")] == ["a"]
    assert graph.incoming_edges("a") == []


def test_attack_graph_is_a_snapshot_not_a_live_view() -> None:
    operation = AttackOperation(name="op", nodes=[AttackNode(id="n1", target="a")])
    graph = attack_graph(operation)
    graph.nodes.append(AttackNode(id="n2", target="b"))
    # Mutating the returned AttackGraph must not mutate the operation it was
    # built from -- it's a read-only query surface, not shared state.
    assert len(operation.nodes) == 1


def test_attack_node_state_defaults_to_known() -> None:
    node = AttackNode(id="n1", target="a")
    assert node.state == AttackNodeState.KNOWN
    assert node.state.value == "known"


def test_attack_operation_with_legacy_known_state_json_still_loads(tmp_path: Path) -> None:
    """A record written before AttackNode.state was a typed enum (or by any
    code that only ever set the literal string "known", which is every path
    that exists today) must still load without error."""
    operations_dir = tmp_path / "operations"
    operations_dir.mkdir()
    legacy_json = (
        '{"name": "op", "objective": "", "engagement": null, '
        '"nodes": [{"id": "n1", "target": "a", "label": "", "state": "known"}], '
        '"edges": [], "actions": [], "approvals": []}'
    )
    (operations_dir / "op.json").write_text(legacy_json)

    store = AttackOperationStore(operations_dir)
    loaded = store.load("op")
    assert loaded.nodes[0].state == AttackNodeState.KNOWN
