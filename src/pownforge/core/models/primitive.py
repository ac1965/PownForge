from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from pownforge.core.models.finding import Finding


class Capability(str, Enum):
    """What effect an action can have, used both by the AttackOperation graph
    and by a validation primitive's descriptor (core/operation.py). Ordered
    loosely from least to most sensitive; PERSISTENCE/NETWORK_PIVOT are the
    ones a SafetyPolicy gates explicitly."""

    READ_ONLY = "read-only"
    STATE_CHANGING = "state-changing"
    CREDENTIAL_RELATED = "credential-related"
    NETWORK_PIVOT = "network-pivot"
    PERSISTENCE = "persistence"


# --------------------------------------------------------------------------
# Validation-primitive framework (data models only; the lifecycle ABC and
# runner live in core/operation.py, the authorization in core/policy.py).
#
# The design goal (docs/handbook.md §15) is to make "what was validated, what
# was observed, and how it was reverted" the center of the model -- NOT to
# ship weaponized exploit payloads. PownForge itself still never executes an
# exploit: a primitive's highest reachable stage is a *controlled* action
# (e.g. observing whether a lab target calls back to a lab-controlled
# listener), gated by SafetyPolicy, and EXECUTION is off unless a dedicated
# lab explicitly enables it. See KillChainPhase for the same invariant.
# --------------------------------------------------------------------------


class ValidationLevel(str, Enum):
    """How far a primitive run is allowed/able to go. Strictly ordered:
    DETECTION < VALIDATION < EXECUTION (see _VALIDATION_LEVEL_ORDER)."""

    # "A sink/condition that *could* be exploitable is present."
    DETECTION = "detection"
    # "Controlled input confirmed a precondition" -- e.g. an out-of-band
    # callback to a lab-controlled listener was observed. No code execution.
    VALIDATION = "validation"
    # "A controlled effect was observed in an authorized lab." Only reachable
    # when SafetyPolicy.execution_enabled is true.
    EXECUTION = "execution"


_VALIDATION_LEVEL_ORDER: dict[ValidationLevel, int] = {
    ValidationLevel.DETECTION: 0,
    ValidationLevel.VALIDATION: 1,
    ValidationLevel.EXECUTION: 2,
}


def validation_level_at_most(a: ValidationLevel, b: ValidationLevel) -> ValidationLevel:
    """Return whichever of A/B is the lower (safer) stage."""
    return a if _VALIDATION_LEVEL_ORDER[a] <= _VALIDATION_LEVEL_ORDER[b] else b


def validation_level_exceeds(a: ValidationLevel, b: ValidationLevel) -> bool:
    """True if stage A is strictly higher (less safe) than stage B."""
    return _VALIDATION_LEVEL_ORDER[a] > _VALIDATION_LEVEL_ORDER[b]


class AllowedAction(str, Enum):
    """Action classes a SafetyPolicy may permit. Coarser than a plugin name;
    a primitive declares which class its controlled action falls under."""

    DISCOVERY = "discovery"
    FINGERPRINT = "fingerprint"
    VALIDATION = "validation"
    EXECUTION = "execution"


class PreconditionStatus(str, Enum):
    MET = "met"          # ✓
    UNMET = "unmet"      # ✗
    UNKNOWN = "unknown"  # ?  (could not be determined without going further)


class Precondition(BaseModel):
    """One named, first-class condition that must hold for a technique to be
    exploitable. Modeling these explicitly lets PownForge report "P1 ✓ / P4 ?
    / P6 ?" instead of a bare "vulnerable/not" boolean."""

    id: str
    description: str
    status: PreconditionStatus = PreconditionStatus.UNKNOWN
    detail: str | None = None


class PreconditionReport(BaseModel):
    preconditions: list[Precondition] = Field(default_factory=list)

    def by_status(self, status: PreconditionStatus) -> list[Precondition]:
        return [p for p in self.preconditions if p.status == status]

    @property
    def all_met(self) -> bool:
        return bool(self.preconditions) and all(
            p.status == PreconditionStatus.MET for p in self.preconditions
        )

    @property
    def has_unmet(self) -> bool:
        return any(p.status == PreconditionStatus.UNMET for p in self.preconditions)

    @property
    def has_unknown(self) -> bool:
        return any(p.status == PreconditionStatus.UNKNOWN for p in self.preconditions)

    def blocks_execution(self) -> bool:
        """Execution should be skipped unless every precondition is met."""
        return not self.all_met


class ProvenanceKind(str, Enum):
    # A fact PownForge itself observed (a received connection, a stored file).
    OBSERVED = "observed"
    # A conclusion a plugin/LLM inferred from observations -- never a fact.
    INFERRED = "inferred"


class Provenance(BaseModel):
    kind: ProvenanceKind
    primitive: str
    run_id: str | None = None
    plugin: str | None = None


class Observation(BaseModel):
    """Layer 1: something actually observed during a run (an inbound
    connection, a created process, a written file). Always provenance
    OBSERVED -- an observation is a fact, not a conclusion."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    type: str
    detail: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provenance: Provenance


class Artifact(BaseModel):
    """Layer 2: a stored piece of proof (a transcript, a log excerpt, a
    capture). Referenced by path + hash so it can be integrity-checked like
    run Evidence."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    type: str
    description: str = ""
    path: str | None = None
    sha256: str | None = None


class ConfidenceLevel(str, Enum):
    TENTATIVE = "tentative"
    PROBABLE = "probable"
    CONFIRMED = "confirmed"


class Claim(BaseModel):
    """Layer 4: a higher-level assertion derived from findings/observations
    (e.g. "a remote-code-execution precondition was confirmed"). Always
    inferred, always backed by the ids of the observations/findings that
    support it -- never stands on its own."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    statement: str
    confidence: ConfidenceLevel = ConfidenceLevel.TENTATIVE
    supported_by: list[str] = Field(default_factory=list)


class PrimitiveEvidence(BaseModel):
    """The 4-layer evidence bundle a primitive run produces. Keeps observed
    facts (observations/artifacts) separate from inferred conclusions
    (findings/claims), so an audit can always tell them apart."""

    evidence_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    primitive: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    observations: list[Observation] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)


class ResourceStatus(str, Enum):
    CREATED = "created"
    CLEANUP_PENDING = "cleanup-pending"
    CLEANUP_ATTEMPTED = "cleanup-attempted"
    VERIFIED_ABSENT = "verified-absent"
    CLEANUP_FAILED = "cleanup-failed"


class ManagedResource(BaseModel):
    """A side effect a primitive created in the lab (a temp file, a listener,
    a temporary account/config) that must be reverted. Tracked from creation
    through verified removal so a failed cleanup becomes evidence rather than
    a silently-leaked artifact."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    type: str
    owner: str  # the primitive-run id that created it
    description: str = ""
    cleanup_required: bool = True
    status: ResourceStatus = ResourceStatus.CREATED


class CleanupResult(BaseModel):
    resource_id: str
    attempted: bool = False
    verified_absent: bool = False
    error: str | None = None


class SafetyPolicy(BaseModel):
    """The action envelope layered under ScopePolicy (docs/handbook.md §15).
    ScopePolicy answers "is this target in scope?"; SafetyPolicy answers "how
    far may a primitive go against an in-scope target?". The default is the
    conservative "ordinary assessment" profile: detection + controlled
    validation only, no execution/persistence/outbound, cleanup mandatory.
    A dedicated lab opts into more, explicitly."""

    allowed_actions: list[AllowedAction] = Field(
        default_factory=lambda: [
            AllowedAction.DISCOVERY,
            AllowedAction.FINGERPRINT,
            AllowedAction.VALIDATION,
        ]
    )
    max_validation_level: ValidationLevel = ValidationLevel.VALIDATION
    execution_enabled: bool = False
    persistence_enabled: bool = False
    external_network_enabled: bool = False
    cleanup_required: bool = True


class PrimitiveDescriptor(BaseModel):
    """Static, declarative metadata for a validation primitive: what it is,
    the coarsest action class it performs (for SafetyPolicy), how far it can
    go, and which sensitive capabilities/needs it declares. The concrete
    lifecycle (prepare/execute/observe/cleanup) is the ValidationPrimitive
    ABC in core/operation.py; this is the part policy reasons about."""

    id: str
    category: str = ""
    description: str = ""
    action_class: AllowedAction = AllowedAction.VALIDATION
    max_level: ValidationLevel = ValidationLevel.VALIDATION
    capabilities: list[Capability] = Field(default_factory=lambda: [Capability.READ_ONLY])
    requires_external_network: bool = False
    requires_persistence: bool = False


class PrimitiveRunRecord(BaseModel):
    """The persisted result of one primitive run: what was tested, why it was
    testable (preconditions), what was observed (evidence), what was changed
    and whether it was cleaned (resources/cleanup). Mirrors the final Finding
    shape from docs/handbook.md §15."""

    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    primitive: str
    category: str = ""
    target: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    requested_level: ValidationLevel
    level_reached: ValidationLevel
    preconditions: PreconditionReport = Field(default_factory=PreconditionReport)
    evidence: PrimitiveEvidence | None = None
    resources: list[ManagedResource] = Field(default_factory=list)
    cleanup: list[CleanupResult] = Field(default_factory=list)
    # Resources still present (cleanup failed or unverified) after the run --
    # a first-class result, not just an error (docs/handbook.md §15).
    residual_resources: list[ManagedResource] = Field(default_factory=list)
    notes: str = ""
    # CVE ids this validation relates to (e.g. "CVE-2021-44228"), set via
    # `primitive run --cve`. Correlation label for the engagement report's CVE
    # exposure matrix -- never inferred, never gates anything.
    cves: list[str] = Field(default_factory=list)
