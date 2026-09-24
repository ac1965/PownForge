from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from pownforge.core.models import Capability


class AttackPhase(str, Enum):
    RECON = "recon"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    PERSISTENCE = "persistence"
    IMPACT = "impact"


class ActionKind(str, Enum):
    SCAN = "scan"
    MANUAL = "manual"
    PIVOT = "pivot"


class ActionStatus(str, Enum):
    PLANNED = "planned"
    APPROVED = "approved"
    COMPLETED = "completed"
    REJECTED = "rejected"


class AttackNodeState(str, Enum):
    """A node's own progress in the attack graph, as distinct from any one
    Action's lifecycle (ActionStatus) -- a node can be the target of several
    Actions over time, so its state isn't simply one Action's status. Not
    auto-derived from Actions (that would need a policy for what happens
    when a node has actions in different states, which nothing currently
    needs); it's set explicitly, the same way it always has been, just
    through a validated enum now instead of an untyped string (refactor
    §5.3.1). KNOWN keeps the exact value every existing AttackNode on disk
    already has (every node has always defaulted to it, and nothing sets
    any other value yet -- see AGENTS.md 識別子/既存データ互換 principle)."""

    KNOWN = "known"
    CANDIDATE = "candidate"
    PLANNED = "planned"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class AttackNode(BaseModel):
    id: str
    target: str
    label: str = ""
    state: AttackNodeState = AttackNodeState.KNOWN


class AttackEdge(BaseModel):
    source: str
    destination: str
    relationship: str = "reachable"
    capabilities: list[Capability] = Field(default_factory=list)


class Action(BaseModel):
    id: str
    name: str
    phase: AttackPhase
    kind: ActionKind
    target: str
    plugin: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)
    # Free-text notes on what this action assumes -- never evaluated,
    # kept only as a human-readable annotation (unlike `requires` below).
    prerequisites: list[str] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=lambda: [Capability.READ_ONLY])
    # requires/provides (refactor §13): a machine-checked dependency graph
    # between Actions in the same operation, distinct from `capabilities`
    # above (Capability classifies *this action's own effect*, e.g.
    # read-only/credential-related -- see core/models/primitive.py and
    # docs/handbook.md's terminology table). Both are free-text tags
    # (e.g. "credential", "admin-session-on-10.0.0.5"); `requires` lists
    # what this action needs before it can run, `provides` lists what it
    # makes available once it reaches ActionStatus.COMPLETED. Evaluated by
    # OperationRunner.execute() via find_unmet_requirements() below --
    # nothing else in this module interprets them.
    requires: list[str] = Field(default_factory=list)
    provides: list[str] = Field(default_factory=list)
    status: ActionStatus = ActionStatus.PLANNED
    run_id: str | None = None


class Approval(BaseModel):
    id: str
    action_id: str
    approved_by: str
    approved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: str = ""


class AttackOperation(BaseModel):
    name: str
    objective: str = ""
    engagement: str | None = None
    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    approvals: list[Approval] = Field(default_factory=list)


class OperationError(RuntimeError):
    pass


def find_action(operation: AttackOperation, action_id: str) -> Action:
    for action in operation.actions:
        if action.id == action_id:
            return action
    raise OperationError(f"no action named '{action_id}'")


def find_approval(operation: AttackOperation, action_id: str) -> Approval:
    matches = [a for a in operation.approvals if a.action_id == action_id]
    if not matches:
        raise OperationError(f"action '{action_id}' has no human approval")
    return matches[-1]


def provided_tags(operation: AttackOperation) -> set[str]:
    """Every `provides` tag made available by an already-COMPLETED action
    in OPERATION (refactor §13) -- the one place "provides is satisfied
    once an action completes" is defined. A PLANNED/APPROVED/REJECTED
    action's `provides` is not yet available, however it's worded."""
    return {tag for action in operation.actions if action.status == ActionStatus.COMPLETED for tag in action.provides}


def find_unmet_requirements(operation: AttackOperation, action: Action) -> list[str]:
    """The `requires` tags ACTION needs that no COMPLETED action in
    OPERATION currently provides (refactor §13). Empty when every
    requirement is satisfied, or ACTION.requires is empty. Preserves
    ACTION.requires's order; a tag listed twice appears at most once."""
    available = provided_tags(operation)
    seen: set[str] = set()
    unmet: list[str] = []
    for tag in action.requires:
        if tag not in available and tag not in seen:
            unmet.append(tag)
            seen.add(tag)
    return unmet
