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


class AttackNode(BaseModel):
    id: str
    target: str
    label: str = ""
    state: str = "known"


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
    prerequisites: list[str] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=lambda: [Capability.READ_ONLY])
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
