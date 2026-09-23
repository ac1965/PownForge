from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TargetKind(str, Enum):
    HOST = "host"
    URL = "url"


class TargetType(str, Enum):
    """Assessment domain of a target, independent of `kind` (which only
    describes the address format). Purely descriptive: it groups/labels
    targets for reporting and the target list, and does not itself gate
    which plugins may run (that remains `allowed_plugins`). For a
    `kubernetes` target, `address` holds a kubeconfig context name rather
    than a host/URL. For a `container` target, `address` holds an image
    reference (e.g. "nginx:1.25"). See docs/handbook.md §6 (プラグイン)."""

    NETWORK = "network"
    WEB = "web"
    API = "api"
    KUBERNETES = "kubernetes"
    CONTAINER = "container"


class TargetEnvironment(str, Enum):
    """How exposed/authoritative a target is. `PRODUCTION` targets require
    `notes` documenting the authorization/engagement reference (enforced by
    ScopePolicy.add_target(), not just a UI convention)."""

    LOCAL_LAB = "local-lab"
    STAGING = "staging"
    PRODUCTION = "production"


class Target(BaseModel):
    name: str
    kind: TargetKind
    address: str
    allowed_plugins: list[str] = Field(default_factory=list)
    notes: str | None = None
    type: TargetType | None = None
    environment: TargetEnvironment = TargetEnvironment.LOCAL_LAB
    # A registered target that's temporarily off-limits (e.g. a maintenance
    # window, a stakeholder asked to pause). Distinct from allowed_plugins
    # (which plugin names are authorized) -- this blocks every plugin,
    # including "manual"/pivot recording, until `target include` clears it.
    # See ScopePolicy.authorize() and docs/handbook.md §12.
    excluded: bool = False
    exclusion_reason: str | None = None
    # How many scans against this target ScanRunner will let run at once,
    # across every process (CLI invocations and the Web UI both go through
    # the same file-lock-based ConcurrencyGuard). None = unlimited (the
    # existing, unrestricted behavior). See core/concurrency.py.
    max_concurrent: int | None = None


class Engagement(BaseModel):
    """A named group of already-registered Targets that are mutually
    authorized to be referenced together, e.g. "target A was used to reach
    target B" (a pivot/lateral-movement step). Membership alone grants no
    execution rights -- each member Target still needs its own
    `allowed_plugins` to be scanned, and PownForge never executes a pivot
    itself. See ScopePolicy.authorize_pivot() and docs/handbook.md §11."""

    name: str
    targets: list[str] = Field(default_factory=list)
    notes: str | None = None


class PluginOption(BaseModel):
    """One `--option key=value` a plugin accepts. Values always arrive as
    strings (CLI/Web/playbook YAML), so there is no type field."""

    name: str
    description: str
    required: bool = False
    default: str | None = None
    choices: list[str] | None = None
    """Case-insensitive allowed values; None = free-form."""


class PluginMetadata(BaseModel):
    name: str
    version: str
    description: str
    required_tool: str
    expected_kind: TargetKind | None = None
    kind_hint: str | None = None
    options: list[PluginOption] | None = None
    """None = the plugin declares no option schema (not validated)."""
    accepts_extra_options: bool = False
    tool_available: bool
    source: str = "builtin"
    """"builtin", or the distribution name an external plugin came from."""


class Evidence(BaseModel):
    command: list[str]
    started_at: datetime
    finished_at: datetime
    returncode: int
    stdout_sha256: str
    stderr_sha256: str
    # Best-effort output of the plugin's version_command() (e.g. "Nmap
    # version 7.991 ( https://nmap.org )"), captured at scan time so a
    # finding's absence/presence can later be checked against which tool
    # version actually ran. None when the plugin doesn't report a version
    # command, the tool is missing, or the version query itself failed.
    tool_version: str | None = None


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    NEEDS_REVIEW = "needs-review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false-positive"


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str
    severity: Severity = Severity.INFO
    detail: str = ""
    # "ai": produced by `pownforge analyze` from unverified LLM output.
    # "tool": produced by a plugin's own tool-native detection (e.g. a nuclei
    # template match), via the "_findings" convention in Plugin.normalize().
    # "manual": entered/reviewed by a human. None of these is ever a
    # confirmed vulnerability by itself — see FindingStatus.
    source: str = "manual"
    # Every finding starts unverified, regardless of source: a tool (or an
    # LLM) saying "vulnerable" is a candidate, not a confirmed result. Only a
    # human review (`pownforge result review`) moves it to confirmed or
    # false-positive.
    status: FindingStatus = FindingStatus.NEEDS_REVIEW


class PlaybookStepCondition(BaseModel):
    """Gates a PlaybookStep on whether an earlier step in the same Playbook
    produced a Finding at or above MIN_SEVERITY. Evaluated purely
    deterministically against already-stored Finding.severity values --
    never by an LLM at run time, and never by inspecting a plugin's raw
    output (which has a different shape per plugin) -- see
    core/orchestrator.py."""

    after_step: int
    min_severity: Severity


class PlaybookStep(BaseModel):
    plugin: str
    options: dict[str, str] = Field(default_factory=dict)
    when: PlaybookStepCondition | None = None


class Playbook(BaseModel):
    """A human-authored, version-controlled sequence of plugin runs against
    one target -- `pownforge playbook run <name> --target <t>` executes each
    step in order via the same ScanRunner/ScopePolicy path a manual
    `pownforge scan <plugin>` would use. A step's `when` (see
    PlaybookStepCondition) may skip it based on an earlier step's findings,
    but that condition is fixed at Playbook-authoring time -- what plugin
    runs when is always decided by whoever wrote the Playbook file, never by
    an LLM at run time -- see core/orchestrator.py and docs/handbook.md §8."""

    name: str
    description: str = ""
    steps: list[PlaybookStep] = Field(default_factory=list)


class Suggestion(BaseModel):
    """An AI-generated "what to try next" recommendation produced by
    `pownforge walkthrough generate` (core/walkthrough.py). Deliberately not
    a Finding: it isn't a vulnerability candidate to confirm/reject, has no
    status/review workflow, and is never persisted (a walkthrough never
    writes to any RunRecord). It carries no execution authority either —
    running the suggested plugin still requires a human to explicitly call
    `pownforge scan <plugin>`."""

    suggestion_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str
    plugin: str | None = None
    rationale: str = ""


class KillChainPhase(str, Enum):
    """Where a recorded run sits in a full attacker kill chain, for
    reporting/tracking purposes only -- this labels evidence, it never
    grants execution authority. PownForge's own plugins (ScanRunner) only
    ever produce DISCOVERY/VULN_CONFIRM-phase evidence; everything from
    EXPLOIT onward can only be attached via `pownforge result import`
    (a human describing what they did with another tool), never executed
    by PownForge itself. See core/manual_evidence.py and
    docs/handbook.md §11."""

    DISCOVERY = "discovery"
    VULN_CONFIRM = "vuln-confirm"
    EXPLOIT = "exploit"
    INITIAL_ACCESS = "initial-access"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    LATERAL_MOVEMENT = "lateral-movement"
    PERSISTENCE = "persistence"
    IMPACT = "impact"


class RunRecord(BaseModel):
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    plugin: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Evidence
    output: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    analysis: str | None = None
    # Set only for a manually-imported run recorded as a pivot step (see
    # ScopePolicy.authorize_pivot()): the name of the Target this run's
    # `target` was reached via/from, and the Engagement both belong to.
    # None for every ordinary scan/manual run that isn't part of a
    # lateral-movement chain.
    via_target: str | None = None
    engagement: str | None = None
    # Set by the operator on `pownforge result import` (never inferred, and
    # never set for a plugin-run scan). Purely descriptive metadata for
    # reports/walkthroughs -- see KillChainPhase.
    kill_chain_phase: KillChainPhase | None = None


class AttackSessionStage(BaseModel):
    """One entry in an AttackSession: a reference to an already-recorded
    RunRecord, plus an optional human-written note explaining its role in
    the story (e.g. "Initial foothold via Shellshock"). Never creates or
    modifies the referenced run."""

    run_id: str
    label: str = ""


class AttackSession(BaseModel):
    """A named, human-curated, persisted ordering of already-recorded runs
    (RunRecord ids, from plugin scans or `result import`), used purely to
    organize/visualize an engagement's story across reports/Emacs/Web UI.

    This is a read-only grouping+labeling layer over EvidenceStore: it
    never creates a run, never executes anything, and grants no new
    authorization beyond what each referenced run already went through
    (ScopePolicy via ScanRunner or `result import`). It's the persisted,
    named counterpart to an ad-hoc `pownforge walkthrough generate
    <run-id>...` invocation -- see core/attack_session.py and
    docs/handbook.md §11."""

    name: str
    description: str = ""
    # Purely a cross-reference for readers, e.g. "this session's stages all
    # belong to Engagement X" -- not validated against ScopePolicy, since
    # AttackSessionStore (like EvidenceStore) never needs a policy handle.
    engagement: str | None = None
    stages: list[AttackSessionStage] = Field(default_factory=list)


class PolicyViolation(BaseModel):
    """A scan attempt that ScopePolicy.authorize() rejected. No Evidence
    exists for these (no command ever ran), so they're tracked separately
    from RunRecord rather than forced into that shape."""

    violation_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target: str
    plugin: str
    reason: str


class HashCheck(BaseModel):
    ok: bool
    expected: str
    actual: str


class EvidenceVerification(BaseModel):
    """Result of recomputing a run's stdout/stderr hashes from its stored
    output and comparing them against evidence.stdout_sha256/stderr_sha256.

    This only catches accidental or partial changes to the run's JSON file
    (a bad manual edit, disk corruption, a bug that mutates output without
    touching evidence). Anyone with write access to the file can edit both
    the output and the hash together, so this is not tamper-proof against a
    deliberate adversary with the same access — see AGENTS.md.
    """

    run_id: str
    stdout: HashCheck
    stderr: HashCheck
    ok: bool


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
