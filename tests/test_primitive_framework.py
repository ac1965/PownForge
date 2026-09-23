from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.models import (
    AllowedAction,
    Capability,
    Observation,
    Precondition,
    PreconditionReport,
    PreconditionStatus,
    PrimitiveDescriptor,
    ResourceStatus,
    SafetyPolicy,
    ValidationLevel,
)
from pownforge.core.operation import (
    PrimitiveContext,
    PrimitiveRunner,
    ResourceRegistry,
    ValidationPrimitive,
)
from pownforge.core.policy import SafetyError, ScopePolicy
from pownforge.core.models import Target, TargetKind
from pownforge.evidence.audit import AuditStore


# An inert fixture primitive: it performs no security-relevant action at all.
# It exists only to exercise the lifecycle/runner scaffolding -- prepare
# registers a bookkeeping resource, execute flips a scratch flag, observe
# reports what happened. There is no target interaction and no payload.
class NoopPrimitive(ValidationPrimitive):
    def __init__(
        self,
        *,
        max_level: ValidationLevel = ValidationLevel.EXECUTION,
        action_class: AllowedAction = AllowedAction.VALIDATION,
        precondition_status: PreconditionStatus = PreconditionStatus.MET,
        requires_persistence: bool = False,
        requires_external_network: bool = False,
        cleanup_ok: bool = True,
    ) -> None:
        self._max_level = max_level
        self._action_class = action_class
        self._precondition_status = precondition_status
        self._requires_persistence = requires_persistence
        self._requires_external_network = requires_external_network
        self._cleanup_ok = cleanup_ok

    def describe(self) -> PrimitiveDescriptor:
        caps = [Capability.READ_ONLY]
        if self._requires_persistence:
            caps.append(Capability.PERSISTENCE)
        return PrimitiveDescriptor(
            id="test.noop",
            category="test",
            description="inert lifecycle fixture",
            action_class=self._action_class,
            max_level=self._max_level,
            capabilities=caps,
            requires_persistence=self._requires_persistence,
            requires_external_network=self._requires_external_network,
        )

    def evaluate_preconditions(self, ctx: PrimitiveContext) -> PreconditionReport:
        return PreconditionReport(
            preconditions=[Precondition(id="P1", description="fixture", status=self._precondition_status)]
        )

    def prepare(self, ctx: PrimitiveContext) -> None:
        ctx.registry.register("test-artifact", "temporary fixture resource")
        ctx.scratch["prepared"] = True

    def execute(self, ctx: PrimitiveContext) -> None:
        # The EXECUTION-depth effect only happens at EXECUTION level; at
        # VALIDATION this controlled action is a no-op for the fixture.
        if ctx.effective_level == ValidationLevel.EXECUTION:
            ctx.scratch["executed"] = True

    def observe(self, ctx: PrimitiveContext) -> list[Observation]:
        obs = [self._observed("lifecycle", f"prepared={ctx.scratch.get('prepared', False)}", ctx.run_id)]
        if ctx.scratch.get("executed"):
            obs.append(self._observed("lifecycle", "executed", ctx.run_id))
        return obs

    def cleanup(self, ctx: PrimitiveContext):
        if self._cleanup_ok:
            return super().cleanup(ctx)
        # Simulate a cleanup that ran but couldn't verify removal.
        from pownforge.core.models import CleanupResult

        results = []
        for resource in ctx.registry.pending_cleanup():
            ctx.registry.mark(resource.id, ResourceStatus.CLEANUP_FAILED)
            results.append(
                CleanupResult(resource_id=resource.id, attempted=True, verified_absent=False, error="boom")
            )
        return results


def _scope(tmp_path: Path, safety: SafetyPolicy | None = None) -> ScopePolicy:
    policy = ScopePolicy(targets={}, safety=safety)
    policy.add_target(Target(name="lab", kind=TargetKind.URL, address="http://lab:8080"))
    return policy


def test_default_run_reaches_validation_and_cleans_up(tmp_path: Path) -> None:
    runner = PrimitiveRunner(_scope(tmp_path))
    record = runner.run(NoopPrimitive(), "lab")  # default requested = VALIDATION
    assert record.level_reached == ValidationLevel.VALIDATION
    assert record.preconditions.all_met
    assert [o.type for o in record.evidence.observations] == ["lifecycle"]
    # every observation is an observed fact, never an inference
    assert all(o.provenance.kind.value == "observed" for o in record.evidence.observations)
    assert len(record.resources) == 1
    assert record.resources[0].status == ResourceStatus.VERIFIED_ABSENT
    assert record.residual_resources == []


def test_execution_requires_execution_enabled(tmp_path: Path) -> None:
    runner = PrimitiveRunner(_scope(tmp_path))  # default safety: execution off
    with pytest.raises(SafetyError, match="execution_enabled"):
        runner.run(NoopPrimitive(), "lab", ValidationLevel.EXECUTION)


def test_execution_runs_in_a_lab_that_enables_it(tmp_path: Path) -> None:
    safety = SafetyPolicy(
        allowed_actions=[AllowedAction.VALIDATION, AllowedAction.EXECUTION],
        max_validation_level=ValidationLevel.EXECUTION,
        execution_enabled=True,
    )
    runner = PrimitiveRunner(_scope(tmp_path, safety))
    record = runner.run(NoopPrimitive(), "lab", ValidationLevel.EXECUTION)
    assert record.level_reached == ValidationLevel.EXECUTION
    assert any(o.detail == "executed" for o in record.evidence.observations)


def test_execution_skipped_when_a_precondition_is_not_met(tmp_path: Path) -> None:
    safety = SafetyPolicy(
        allowed_actions=[AllowedAction.VALIDATION, AllowedAction.EXECUTION],
        max_validation_level=ValidationLevel.EXECUTION,
        execution_enabled=True,
    )
    runner = PrimitiveRunner(_scope(tmp_path, safety))
    primitive = NoopPrimitive(precondition_status=PreconditionStatus.UNKNOWN)
    record = runner.run(primitive, "lab", ValidationLevel.EXECUTION)
    assert record.level_reached == ValidationLevel.VALIDATION
    assert "execution skipped" in record.notes
    assert not any(o.detail == "executed" for o in record.evidence.observations)


def test_requested_level_is_clamped_to_primitive_max(tmp_path: Path) -> None:
    runner = PrimitiveRunner(_scope(tmp_path))
    primitive = NoopPrimitive(max_level=ValidationLevel.DETECTION)
    record = runner.run(primitive, "lab", ValidationLevel.VALIDATION)
    assert record.level_reached == ValidationLevel.DETECTION
    # detection-only: prepare/execute never ran, so no resource was created
    assert record.resources == []


def test_action_class_not_allowed_is_refused_and_audited(tmp_path: Path) -> None:
    audit = AuditStore(tmp_path / "violations")
    safety = SafetyPolicy(allowed_actions=[AllowedAction.DISCOVERY])
    runner = PrimitiveRunner(_scope(tmp_path, safety), audit=audit)
    with pytest.raises(SafetyError, match="allowed_actions"):
        runner.run(NoopPrimitive(action_class=AllowedAction.VALIDATION), "lab")
    violations = audit.list()
    assert len(violations) == 1
    assert violations[0].plugin == "primitive:test.noop"


def test_persistence_and_outbound_are_gated(tmp_path: Path) -> None:
    runner = PrimitiveRunner(_scope(tmp_path))
    with pytest.raises(SafetyError, match="persistence"):
        runner.run(NoopPrimitive(requires_persistence=True), "lab")
    with pytest.raises(SafetyError, match="outbound"):
        runner.run(NoopPrimitive(requires_external_network=True), "lab")


def test_excluded_target_is_refused(tmp_path: Path) -> None:
    policy = _scope(tmp_path)
    policy.exclude_target("lab", "maintenance window")
    runner = PrimitiveRunner(policy)
    with pytest.raises(Exception, match="excluded"):
        runner.run(NoopPrimitive(), "lab")


def test_failed_cleanup_surfaces_as_residual(tmp_path: Path) -> None:
    runner = PrimitiveRunner(_scope(tmp_path))
    record = runner.run(NoopPrimitive(cleanup_ok=False), "lab")
    assert record.cleanup[0].verified_absent is False
    assert len(record.residual_resources) == 1
    assert record.residual_resources[0].status == ResourceStatus.CLEANUP_FAILED


def test_precondition_report_states() -> None:
    report = PreconditionReport(
        preconditions=[
            Precondition(id="P1", description="a", status=PreconditionStatus.MET),
            Precondition(id="P2", description="b", status=PreconditionStatus.UNKNOWN),
        ]
    )
    assert not report.all_met
    assert report.has_unknown
    assert not report.has_unmet
    assert report.blocks_execution()
    assert [p.id for p in report.by_status(PreconditionStatus.MET)] == ["P1"]


def test_safety_policy_round_trips_through_scope_config(tmp_path: Path) -> None:
    safety = SafetyPolicy(execution_enabled=True, max_validation_level=ValidationLevel.EXECUTION)
    policy = ScopePolicy(targets={}, safety=safety)
    policy.add_target(Target(name="lab", kind=TargetKind.URL, address="http://lab:8080"))
    path = tmp_path / "targets.yaml"
    policy.save(path)
    reloaded = ScopePolicy.load(path)
    assert reloaded.safety.execution_enabled is True
    assert reloaded.safety.max_validation_level == ValidationLevel.EXECUTION


def test_scope_config_without_safety_block_uses_conservative_default(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text("targets: {}\nengagements: {}\n")
    reloaded = ScopePolicy.load(path)
    assert reloaded.safety.execution_enabled is False
    assert reloaded.safety.max_validation_level == ValidationLevel.VALIDATION


def test_resource_registry_tracks_lifecycle() -> None:
    registry = ResourceRegistry(owner="run1")
    resource = registry.register("temp-file", "scratch")
    assert registry.pending_cleanup() == [resource]
    registry.mark(resource.id, ResourceStatus.VERIFIED_ABSENT)
    assert registry.pending_cleanup() == []
    assert registry.residual() == []
