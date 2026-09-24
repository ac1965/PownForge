from __future__ import annotations

from pownforge.core.models import (
    PreconditionStatus,
    PrimitiveRunRecord,
    ValidationLevel,
    validation_level_exceeds,
)
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.primitives.base import ValidationPrimitive
from pownforge.core.primitives.context import PrimitiveContext
from pownforge.core.primitives.resources import ResourceRegistry
from pownforge.evidence.audit import AuditStore


def validation_level_reaches(level: ValidationLevel, at_least: ValidationLevel) -> bool:
    """True if LEVEL is AT_LEAST the given stage (inclusive)."""
    return not validation_level_exceeds(at_least, level)


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
