"""Facade package: `from pownforge.core.models import X` keeps working for
every name this package re-exports below, exactly as when this was a single
models.py file (refactor §5.2). Internal layout only -- callers should import
from `pownforge.core.models`, not from a submodule directly, since the
submodule boundaries may still move.
"""

from __future__ import annotations

from pownforge.core.models.attack_session import AttackSession, AttackSessionStage
from pownforge.core.models.evidence import (
    Evidence,
    EvidenceVerification,
    HashCheck,
    KillChainPhase,
    PolicyViolation,
    RunRecord,
)
from pownforge.core.models.execution import ExecutionRequest, ExecutionResult, ExecutionStatus
from pownforge.core.models.finding import Finding, FindingStatus, Severity, Suggestion
from pownforge.core.models.playbook import Playbook, PlaybookStep, PlaybookStepCondition
from pownforge.core.models.plugin import PluginMetadata, PluginOption
from pownforge.core.models.primitive import (
    AllowedAction,
    Artifact,
    Capability,
    Claim,
    CleanupResult,
    ConfidenceLevel,
    ManagedResource,
    Observation,
    Precondition,
    PreconditionReport,
    PreconditionStatus,
    PrimitiveDescriptor,
    PrimitiveEvidence,
    PrimitiveRunRecord,
    Provenance,
    ProvenanceKind,
    ResourceStatus,
    SafetyPolicy,
    ValidationLevel,
    validation_level_at_most,
    validation_level_exceeds,
)
from pownforge.core.models.target import (
    Engagement,
    Target,
    TargetEnvironment,
    TargetKind,
    TargetPathError,
    TargetType,
    resolve_path_target_address,
)

__all__ = [
    "AllowedAction",
    "Artifact",
    "AttackSession",
    "AttackSessionStage",
    "Capability",
    "Claim",
    "CleanupResult",
    "ConfidenceLevel",
    "Engagement",
    "Evidence",
    "EvidenceVerification",
    "ExecutionRequest",
    "ExecutionResult",
    "ExecutionStatus",
    "Finding",
    "FindingStatus",
    "HashCheck",
    "KillChainPhase",
    "ManagedResource",
    "Observation",
    "Playbook",
    "PlaybookStep",
    "PlaybookStepCondition",
    "PluginMetadata",
    "PluginOption",
    "PolicyViolation",
    "Precondition",
    "PreconditionReport",
    "PreconditionStatus",
    "PrimitiveDescriptor",
    "PrimitiveEvidence",
    "PrimitiveRunRecord",
    "Provenance",
    "ProvenanceKind",
    "ResourceStatus",
    "RunRecord",
    "SafetyPolicy",
    "Severity",
    "Suggestion",
    "Target",
    "TargetEnvironment",
    "TargetKind",
    "TargetPathError",
    "TargetType",
    "ValidationLevel",
    "resolve_path_target_address",
    "validation_level_at_most",
    "validation_level_exceeds",
]
