from __future__ import annotations

import fcntl
import os
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator

from pydantic import BaseModel, Field

from pownforge.core.atomic_write import atomic_write_text
from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.identifiers import IdentifierError, validate_identifier
from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.models import (
    Capability,
    CleanupResult,
    KillChainPhase,
    ManagedResource,
    Observation,
    PreconditionReport,
    PreconditionStatus,
    PrimitiveDescriptor,
    PrimitiveEvidence,
    PrimitiveRunRecord,
    Provenance,
    ProvenanceKind,
    ResourceStatus,
    Target,
    ValidationLevel,
    validation_level_exceeds,
)
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
    """One JSON file per AttackOperation. `load`-mutate-`save` is not
    inherently safe against two concurrent callers (CLI + Web UI, or two
    CLI invocations) racing on the same operation -- see `lock()`/`update()`
    and refactor §4.6."""

    # How long lock() waits for a concurrent holder before giving up.
    # Bounded, not blocking forever, so a caller gets an explicit
    # OperationError instead of hanging if a lock is somehow wedged.
    _LOCK_TIMEOUT_SECONDS = 5.0
    _LOCK_POLL_INTERVAL_SECONDS = 0.05

    def __init__(self, operations_dir: Path) -> None:
        self._dir = operations_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def _lock_path(self, name: str) -> Path:
        return self._dir / f".{name}.lock"

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        """Exclusive, cross-process lock over a load-mutate-save sequence
        for operation NAME, via fcntl.flock on a sibling `.<name>.lock`
        file (same approach as ConcurrencyGuard in core/concurrency.py).
        Every module-level mutator below (add_node, add_action, ...) and
        `update()` hold this for their whole load+save; a bare `save()`
        call outside one of those is the caller's own responsibility."""
        lock_path = self._lock_path(name)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + self._LOCK_TIMEOUT_SECONDS
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise OperationError(
                            f"could not acquire the update lock for attack operation "
                            f"'{name}' within {self._LOCK_TIMEOUT_SECONDS}s"
                        )
                    time.sleep(self._LOCK_POLL_INTERVAL_SECONDS)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def update(
        self, name: str, mutate: Callable[[AttackOperation], AttackOperation | None]
    ) -> AttackOperation:
        """Load NAME under lock(), call `mutate(operation)`, save the result
        (or the same operation, mutated in place, if MUTATE returns None),
        and return it -- still holding the lock for the whole sequence so
        two concurrent updates can't silently drop one of them."""
        with self.lock(name):
            operation = self.load(name)
            result = mutate(operation)
            operation = result if result is not None else operation
            self.save(operation)
            return operation

    def save(self, operation: AttackOperation) -> Path:
        path = self._dir / f"{operation.name}.json"
        atomic_write_text(path, operation.model_dump_json(indent=2))
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
        validate_identifier(name, kind="operation")
    except IdentifierError as exc:
        raise OperationError(str(exc)) from exc
    with store.lock(name):
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
    policy.resolve(target)
    with store.lock(operation_name):
        operation = store.load(operation_name)
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
    policy.resolve(source)
    policy.resolve(destination)
    if source == destination:
        raise OperationError("an attack graph edge cannot point to itself")
    with store.lock(operation_name):
        operation = store.load(operation_name)
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
    policy.resolve(action.target)
    with store.lock(operation_name):
        operation = store.load(operation_name)
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
    with store.lock(operation_name):
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


# --------------------------------------------------------------------------
# Validation-primitive lifecycle (see core/models.py for the data models and
# core/policy.py for authorization). A primitive models "validate a technique
# under controlled conditions, observe, and revert" -- NOT a weaponized
# exploit. The base class ships no concrete attack; it's the contract a
# (lab-only, detection/validation-oriented) primitive implements, plus a
# runner that enforces scope+safety, always attempts cleanup, and records
# residual artifacts as first-class results.
# --------------------------------------------------------------------------


class ResourceRegistry:
    """Tracks the side effects a single primitive run creates so cleanup can
    be driven and verified. In-memory per run; the final ManagedResource
    list is persisted as part of the PrimitiveRunRecord."""

    def __init__(self, owner: str) -> None:
        self._owner = owner
        self._resources: dict[str, ManagedResource] = {}

    def register(
        self, type: str, description: str = "", cleanup_required: bool = True
    ) -> ManagedResource:
        resource = ManagedResource(
            type=type, owner=self._owner, description=description, cleanup_required=cleanup_required
        )
        self._resources[resource.id] = resource
        return resource

    def mark(self, resource_id: str, status: ResourceStatus) -> None:
        self._resources[resource_id].status = status

    def resources(self) -> list[ManagedResource]:
        return list(self._resources.values())

    def pending_cleanup(self) -> list[ManagedResource]:
        return [
            r
            for r in self._resources.values()
            if r.cleanup_required and r.status != ResourceStatus.VERIFIED_ABSENT
        ]

    def residual(self) -> list[ManagedResource]:
        """Resources that still require cleanup but aren't verified absent --
        i.e. leaked or failed-to-clean. These become ResidualArtifact evidence."""
        return [
            r
            for r in self._resources.values()
            if r.cleanup_required and r.status != ResourceStatus.VERIFIED_ABSENT
        ]


@dataclass
class PrimitiveContext:
    """Mutable state shared across one primitive run's lifecycle phases.
    `scratch` lets prepare() hand data to execute()/observe() without the
    primitive holding per-run state on itself (keeps primitives reusable)."""

    target: Target
    effective_level: ValidationLevel
    run_id: str
    registry: ResourceRegistry
    scratch: dict[str, Any] = field(default_factory=dict)


class ValidationPrimitive(ABC):
    """The lifecycle contract: describe -> preconditions -> prepare ->
    (execute) -> observe -> cleanup. The runner (PrimitiveRunner) is what
    actually calls these in order under scope+safety enforcement; a primitive
    never runs itself, mirroring the Plugin/ScanRunner split. Subclasses that
    reach an authorized lab's EXECUTION stage still model a *controlled*,
    reversible action -- concrete exploit payloads are out of scope for this
    framework (see module docstring / docs/handbook.md §15)."""

    @abstractmethod
    def describe(self) -> PrimitiveDescriptor: ...

    @abstractmethod
    def evaluate_preconditions(self, ctx: PrimitiveContext) -> PreconditionReport:
        """Assess each precondition against the target, returning met/unmet/
        unknown -- never a bare boolean."""

    def prepare(self, ctx: PrimitiveContext) -> None:
        """Set up controlled test state (register any created resources on
        ctx.registry). Default: nothing to prepare."""

    def execute(self, ctx: PrimitiveContext) -> None:
        """Perform the controlled action for ctx.effective_level. Only called
        when the level and preconditions permit. Default: nothing (a
        detection-only primitive)."""

    @abstractmethod
    def observe(self, ctx: PrimitiveContext) -> list[Observation]:
        """Collect what was actually observed (facts, provenance OBSERVED)."""

    def cleanup(self, ctx: PrimitiveContext) -> list[CleanupResult]:
        """Revert side effects and verify their absence. Default: mark every
        registered resource attempted+verified (suitable for primitives that
        register purely in-memory bookkeeping resources; a primitive with real
        side effects overrides this and does the actual teardown)."""
        results: list[CleanupResult] = []
        for resource in ctx.registry.pending_cleanup():
            ctx.registry.mark(resource.id, ResourceStatus.CLEANUP_ATTEMPTED)
            ctx.registry.mark(resource.id, ResourceStatus.VERIFIED_ABSENT)
            results.append(
                CleanupResult(resource_id=resource.id, attempted=True, verified_absent=True)
            )
        return results

    def build_evidence(
        self, ctx: PrimitiveContext, observations: list[Observation]
    ) -> PrimitiveEvidence:
        """Assemble the 4-layer evidence bundle. Default: observations only
        (facts). A primitive that derives findings/claims from those
        observations overrides this to add them -- keeping the observed/
        inferred split explicit (see core/models.py PrimitiveEvidence)."""
        return PrimitiveEvidence(
            target=ctx.target.name, primitive=self.describe().id, observations=observations
        )

    def _observed(self, type: str, detail: str, run_id: str) -> Observation:
        """Helper for subclasses: build an OBSERVED-provenance observation."""
        return Observation(
            type=type,
            detail=detail,
            provenance=Provenance(
                kind=ProvenanceKind.OBSERVED, primitive=self.describe().id, run_id=run_id
            ),
        )


class PrimitiveRunner:
    """Drives a ValidationPrimitive through its lifecycle under ScopePolicy +
    SafetyPolicy. Scope is authorized first; a refusal (out of scope, or
    beyond the safety envelope) is recorded to AuditStore before raising,
    exactly like ScanRunner. Cleanup is always attempted when the effective
    level did any preparing, and residual (un-reverted) resources are surfaced
    as a first-class part of the record rather than swallowed."""

    def __init__(self, policy: ScopePolicy, audit: AuditStore | None = None) -> None:
        self._policy = policy
        self._audit = audit

    def run(
        self,
        primitive: ValidationPrimitive,
        target_name: str,
        requested_level: ValidationLevel = ValidationLevel.VALIDATION,
    ) -> PrimitiveRunRecord:
        descriptor = primitive.describe()
        try:
            target, effective = self._policy.authorize_primitive(
                target_name, descriptor, requested_level
            )
        except PolicyError as exc:
            if self._audit is not None:
                # plugin slot records the primitive id so the audit trail is
                # legible next to ordinary scan rejections.
                self._audit.record(target_name, f"primitive:{descriptor.id}", str(exc))
            raise

        record = PrimitiveRunRecord(
            primitive=descriptor.id,
            category=descriptor.category,
            target=target_name,
            requested_level=requested_level,
            level_reached=ValidationLevel.DETECTION,
        )
        registry = ResourceRegistry(owner=record.run_id)
        ctx = PrimitiveContext(
            target=target, effective_level=effective, run_id=record.run_id, registry=registry
        )

        report = primitive.evaluate_preconditions(ctx)
        record.preconditions = report

        prepared = False
        try:
            # DETECTION observes only. VALIDATION/EXECUTION prepare + perform a
            # controlled action whose depth is ctx.effective_level; the
            # primitive inspects that to decide how far to go.
            if validation_level_reaches(effective, ValidationLevel.VALIDATION):
                primitive.prepare(ctx)
                prepared = True
                if effective == ValidationLevel.EXECUTION and report.blocks_execution():
                    # A precondition is unmet/unknown: don't perform the
                    # EXECUTION-depth effect. Downgrade the controlled action
                    # to VALIDATION and record why.
                    ctx.effective_level = ValidationLevel.VALIDATION
                    record.notes = (
                        "execution skipped: not all preconditions met "
                        f"({', '.join(p.id for p in report.preconditions if p.status != PreconditionStatus.MET)})"
                    )
                primitive.execute(ctx)
                record.level_reached = ctx.effective_level
            observations = primitive.observe(ctx)
            record.evidence = primitive.build_evidence(ctx, observations)
        finally:
            if prepared:
                record.cleanup = primitive.cleanup(ctx)
            record.resources = registry.resources()
            record.residual_resources = registry.residual()
        return record


def validation_level_reaches(level: ValidationLevel, at_least: ValidationLevel) -> bool:
    """True if LEVEL is AT_LEAST the given stage (inclusive)."""
    return not validation_level_exceeds(at_least, level)
