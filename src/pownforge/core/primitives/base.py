from __future__ import annotations

from abc import ABC, abstractmethod

from pownforge.core.models import (
    CleanupResult,
    Observation,
    PreconditionReport,
    PrimitiveDescriptor,
    PrimitiveEvidence,
    Provenance,
    ProvenanceKind,
    ResourceStatus,
)
from pownforge.core.primitives.context import PrimitiveContext

# --------------------------------------------------------------------------
# Validation-primitive lifecycle (see core/models/primitive.py for the data
# models and core/policy.py for authorization). A primitive models "validate
# a technique under controlled conditions, observe, and revert" -- NOT a
# weaponized exploit. The base class ships no concrete attack; it's the
# contract a (lab-only, detection/validation-oriented) primitive implements,
# plus a runner (core/primitives/runner.py) that enforces scope+safety,
# always attempts cleanup, and records residual artifacts as first-class
# results.
# --------------------------------------------------------------------------


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
        inferred split explicit (see core/models/primitive.py PrimitiveEvidence)."""
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
