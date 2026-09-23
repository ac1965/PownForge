from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.models import KillChainPhase
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore


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


# Maps the finer-grained AttackPhase (this module's MITRE-ATT&CK-flavored
# graph phases) onto the coarser KillChainPhase used for manual evidence
# (core/manual_evidence.py). EXECUTION and CREDENTIAL_ACCESS have no exact
# KillChainPhase counterpart and intentionally map to None -- the run is
# still recorded, just without a kill_chain_phase tag, rather than guessing
# a misleading one.
_KILL_CHAIN_PHASE_BY_ATTACK_PHASE: dict[AttackPhase, KillChainPhase | None] = {
    AttackPhase.RECON: KillChainPhase.DISCOVERY,
    AttackPhase.DISCOVERY: KillChainPhase.DISCOVERY,
    AttackPhase.INITIAL_ACCESS: KillChainPhase.INITIAL_ACCESS,
    AttackPhase.EXECUTION: None,
    AttackPhase.CREDENTIAL_ACCESS: None,
    AttackPhase.PRIVILEGE_ESCALATION: KillChainPhase.PRIVILEGE_ESCALATION,
    AttackPhase.LATERAL_MOVEMENT: KillChainPhase.LATERAL_MOVEMENT,
    AttackPhase.PERSISTENCE: KillChainPhase.PERSISTENCE,
    AttackPhase.IMPACT: KillChainPhase.IMPACT,
}


class Capability(str, Enum):
    READ_ONLY = "read-only"
    STATE_CHANGING = "state-changing"
    CREDENTIAL_RELATED = "credential-related"
    NETWORK_PIVOT = "network-pivot"
    PERSISTENCE = "persistence"


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


class AttackOperationStore:
    def __init__(self, operations_dir: Path) -> None:
        self._dir = operations_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, operation: AttackOperation) -> Path:
        path = self._dir / f"{operation.name}.json"
        path.write_text(operation.model_dump_json(indent=2))
        return path

    def load(self, name: str) -> AttackOperation:
        path = self._dir / f"{name}.json"
        if not path.exists():
            raise OperationError(f"no attack operation named '{name}'")
        return AttackOperation.model_validate_json(path.read_text())

    def list(self) -> list[AttackOperation]:
        return [
            AttackOperation.model_validate_json(path.read_text())
            for path in sorted(self._dir.glob("*.json"))
        ]


def create_operation(
    store: AttackOperationStore,
    name: str,
    objective: str = "",
    engagement: str | None = None,
) -> AttackOperation:
    try:
        store.load(name)
    except OperationError:
        pass
    else:
        raise OperationError(f"attack operation '{name}' already exists")
    operation = AttackOperation(
        name=name,
        objective=objective,
        engagement=engagement,
    )
    store.save(operation)
    return operation


def add_node(
    store: AttackOperationStore,
    policy: ScopePolicy,
    operation_name: str,
    node_id: str,
    target: str,
    label: str = "",
) -> AttackOperation:
    operation = store.load(operation_name)
    policy.resolve(target)
    if any(node.id == node_id for node in operation.nodes):
        raise OperationError(f"node '{node_id}' already exists")
    operation.nodes.append(AttackNode(id=node_id, target=target, label=label))
    store.save(operation)
    return operation


def add_edge(
    store: AttackOperationStore,
    policy: ScopePolicy,
    operation_name: str,
    source: str,
    destination: str,
    capabilities: list[Capability] | None = None,
) -> AttackOperation:
    operation = store.load(operation_name)
    policy.resolve(source)
    policy.resolve(destination)
    if source == destination:
        raise OperationError("an attack graph edge cannot point to itself")
    if not any(node.target == source for node in operation.nodes):
        raise OperationError(f"source target '{source}' is not a graph node")
    if not any(node.target == destination for node in operation.nodes):
        raise OperationError(f"destination target '{destination}' is not a graph node")
    edge = AttackEdge(
        source=source,
        destination=destination,
        capabilities=capabilities or [Capability.NETWORK_PIVOT],
    )
    if edge in operation.edges:
        raise OperationError("attack graph edge already exists")
    operation.edges.append(edge)
    store.save(operation)
    return operation


def add_action(
    store: AttackOperationStore,
    policy: ScopePolicy,
    operation_name: str,
    action: Action,
) -> AttackOperation:
    operation = store.load(operation_name)
    policy.resolve(action.target)
    if any(existing.id == action.id for existing in operation.actions):
        raise OperationError(f"action '{action.id}' already exists")
    if action.kind == ActionKind.SCAN and not action.plugin:
        raise OperationError("scan actions require plugin")
    if action.kind != ActionKind.SCAN and action.plugin:
        raise OperationError("only scan actions may specify a plugin")
    operation.actions.append(action)
    store.save(operation)
    return operation


def approve_action(
    store: AttackOperationStore,
    operation_name: str,
    action_id: str,
    approved_by: str,
    note: str = "",
) -> AttackOperation:
    operation = store.load(operation_name)
    action = _action(operation, action_id)
    if action.status not in {ActionStatus.PLANNED, ActionStatus.REJECTED}:
        raise OperationError(f"action '{action_id}' cannot be approved from status {action.status.value}")
    approval = Approval(
        id=f"approval-{action_id}-{len(operation.approvals) + 1}",
        action_id=action_id,
        approved_by=approved_by,
        note=note,
    )
    operation.approvals.append(approval)
    action.status = ActionStatus.APPROVED
    store.save(operation)
    return operation


def _action(operation: AttackOperation, action_id: str) -> Action:
    for action in operation.actions:
        if action.id == action_id:
            return action
    raise OperationError(f"no action named '{action_id}'")


def _approval(operation: AttackOperation, action_id: str) -> Approval:
    matches = [a for a in operation.approvals if a.action_id == action_id]
    if not matches:
        raise OperationError(f"action '{action_id}' has no human approval")
    return matches[-1]


class OperationRunner:
    """Execute the operation layer without making it an unrestricted shell.

    SCAN actions dispatch to the existing ScanRunner, same as `pownforge
    scan <plugin>`. MANUAL/PIVOT actions never execute anything -- `execute`
    for them only *records* evidence a human already produced with an
    external tool, through the same import_manual_run() path `pownforge
    result import` uses (see core/manual_evidence.py). This keeps the
    AttackOperation model from becoming a generic command-execution engine
    while still letting its graph/approval workflow track manual/pivot
    steps end to end, the same way `result import` already lets an
    unstructured run be recorded.
    """

    def __init__(
        self,
        policy: ScopePolicy,
        registry: PluginRegistry,
        store: EvidenceStore,
        audit: AuditStore | None = None,
        concurrency: ConcurrencyGuard | None = None,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._store = store
        self._audit = audit
        self._concurrency = concurrency

    def execute(
        self,
        operation: AttackOperation,
        action_id: str,
        *,
        manual_command: str | None = None,
        manual_output: str | None = None,
        manual_tool: str | None = None,
        manual_tool_version: str | None = None,
        manual_returncode: int = 0,
    ) -> AttackOperation:
        action = _action(operation, action_id)
        if action.status != ActionStatus.APPROVED:
            raise OperationError(
                f"action '{action_id}' must be approved before execution "
                f"(current status: {action.status.value})"
            )
        _approval(operation, action_id)

        if action.kind == ActionKind.SCAN:
            assert action.plugin is not None
            try:
                record = ScanRunner(
                    policy=self._policy,
                    registry=self._registry,
                    store=self._store,
                    audit=self._audit,
                    concurrency=self._concurrency,
                ).run(action.target, action.plugin, action.options)
            except (PolicyError, RunnerError) as exc:
                action.status = ActionStatus.REJECTED
                raise OperationError(str(exc)) from exc
        else:
            # MANUAL/PIVOT: record-only. PownForge does not run action.name
            # or anything else here -- MANUAL_OUTPUT must already be the
            # transcript of what a human ran with an external tool.
            if manual_output is None:
                raise OperationError(
                    f"action kind '{action.kind.value}' requires --output: PownForge "
                    "never executes it itself, only records evidence a human already "
                    "produced with an external tool (same as `pownforge result import`)"
                )
            via_target: str | None = None
            engagement: str | None = None
            if action.kind == ActionKind.PIVOT:
                if operation.engagement is None:
                    raise OperationError(
                        f"pivot action '{action_id}' requires the operation to have "
                        "an engagement (set at `operation create --engagement`)"
                    )
                incoming = [edge for edge in operation.edges if edge.destination == action.target]
                if not incoming:
                    raise OperationError(
                        f"pivot action '{action_id}' targets '{action.target}', but no "
                        "graph edge has it as a destination -- add one with "
                        "`operation add-edge` first"
                    )
                via_target = incoming[-1].source
                engagement = operation.engagement
            try:
                record = import_manual_run(
                    self._policy,
                    self._store,
                    action.target,
                    manual_command or action.name,
                    manual_output,
                    tool=manual_tool,
                    tool_version=manual_tool_version,
                    returncode=manual_returncode,
                    audit=self._audit,
                    engagement=engagement,
                    via_target=via_target,
                    kill_chain_phase=_KILL_CHAIN_PHASE_BY_ATTACK_PHASE.get(action.phase),
                )
            except PolicyError as exc:
                action.status = ActionStatus.REJECTED
                raise OperationError(str(exc)) from exc

        action.run_id = record.run_id
        action.status = ActionStatus.COMPLETED
        return operation
