from __future__ import annotations

from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.models import KillChainPhase
from pownforge.core.operation.model import (
    ActionKind,
    ActionStatus,
    AttackOperation,
    AttackPhase,
    OperationError,
    find_action,
    find_approval,
)
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore

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
        action = find_action(operation, action_id)
        if action.status != ActionStatus.APPROVED:
            raise OperationError(
                f"action '{action_id}' must be approved before execution "
                f"(current status: {action.status.value})"
            )
        find_approval(operation, action_id)

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
