from __future__ import annotations

from pydantic import BaseModel, Field

from pownforge.core.operation.model import AttackEdge, AttackNode, AttackOperation


class AttackGraph(BaseModel):
    """The graph half of an AttackOperation (refactor §5.3): which targets
    are known (AttackNode) and how they connect (AttackEdge), kept
    conceptually separate from the Action/Approval/execution concerns that
    stay on AttackOperation directly.

    AttackOperation.graph exposes this as a computed view built from its own
    `nodes`/`edges` fields -- the persisted JSON schema is unchanged (still
    top-level "nodes"/"edges" keys on the operation record), so every
    AttackOperation already on disk keeps loading exactly as before. This is
    a responsibility split at the code level, not a data migration; §5.3
    explicitly rules out replacing AttackOperation's own model to keep that
    compatibility.
    """

    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)

    def node(self, node_id: str) -> AttackNode | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def has_target(self, target: str) -> bool:
        return any(n.target == target for n in self.nodes)

    def incoming_edges(self, target: str) -> list[AttackEdge]:
        """Edges whose destination is TARGET, in the order they were added."""
        return [e for e in self.edges if e.destination == target]

    def neighbors(self, target: str) -> list[str]:
        """Targets directly reachable from TARGET via an outgoing edge."""
        return [e.destination for e in self.edges if e.source == target]


def attack_graph(operation: AttackOperation) -> AttackGraph:
    """Build the AttackGraph view of OPERATION's current nodes/edges. A
    standalone function rather than an AttackOperation property/method so
    the dependency stays one-directional (graph.py depends on model.py, not
    the reverse) -- matching the target architecture where AttackGraph and
    Operation are siblings, not one nested in the other (refactor §5.3,
    §14's diagram). The returned AttackGraph is a snapshot: mutating it
    does not mutate OPERATION."""
    return AttackGraph(nodes=operation.nodes, edges=operation.edges)
