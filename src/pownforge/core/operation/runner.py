from __future__ import annotations

from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.models import ExecutionRequest, KillChainPhase, RunRecord
from pownforge.core.operation.graph import attack_graph
from pownforge.core.operation.model import (
    Action,
    ActionKind,
    ActionStatus,
    Approval,
    AttackNodeState,
    AttackOperation,
    AttackPhase,
    OperationError,
    find_action,
    find_approval,
    find_unmet_requirements,
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
    """The ActionExecutor for the operation layer (refactor §15): the one
    place an approved, prerequisite-satisfied Action actually runs,
    without making AttackOperation an unrestricted shell. Kept this name
    (rather than a parallel `ActionExecutor` class) since it already *is*
    that layer -- see `execute()`, the single entry point every Action
    kind goes through.

    SCAN actions dispatch to the existing ScanRunner, same as `pownforge
    scan <plugin>` (see `_execute_scan`). MANUAL/PIVOT actions never
    execute anything -- `execute` for them only *records* evidence a
    human already produced with an external tool, through the same
    import_manual_run() path `pownforge result import` uses (see
    `_execute_manual_or_pivot` and core/manual_evidence.py). This keeps
    the AttackOperation model from becoming a generic command-execution
    engine while still letting its graph/approval workflow track
    manual/pivot steps end to end, the same way `result import` already
    lets an unstructured run be recorded.

    The kind dispatch below is two private methods rather than a
    Provider/Protocol abstraction -- that's worth introducing only once a
    third kind (e.g. a validation Primitive, see core/primitives/) is
    actually wired in as an Action kind (refactor §14, not yet done).
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
        approval = find_approval(operation, action_id)

        # requires/provides (refactor §13): a separate gate from approval
        # above -- being approved never substitutes for an unmet
        # prerequisite. Left at its current status (still APPROVED, never
        # COMPLETED or REJECTED) so re-running `operation execute` once the
        # blocking action completes just works, with no extra command to
        # "unblock" it.
        unmet = find_unmet_requirements(operation, action)
        if unmet:
            raise OperationError(
                f"action '{action_id}' requires {unmet}, which no completed action in "
                "this operation provides yet"
            )

        try:
            if action.kind == ActionKind.SCAN:
                record = self._execute_scan(action, approval)
            else:
                record = self._execute_manual_or_pivot(
                    operation,
                    action,
                    manual_command=manual_command,
                    manual_output=manual_output,
                    manual_tool=manual_tool,
                    manual_tool_version=manual_tool_version,
                    manual_returncode=manual_returncode,
                )
        except (PolicyError, RunnerError) as exc:
            action.status = ActionStatus.REJECTED
            self._sync_node_state(operation, action.target, AttackNodeState.FAILED)
            raise OperationError(str(exc)) from exc

        action.run_id = record.run_id
        action.status = ActionStatus.COMPLETED
        self._sync_node_state(operation, action.target, AttackNodeState.SUCCEEDED)
        return operation

    @staticmethod
    def _sync_node_state(operation: AttackOperation, target: str, state: AttackNodeState) -> None:
        """Set every AttackNode whose `target` matches TARGET to STATE
        (refactor §12) -- the one place Action execution updates node
        state, and the only place that does: add_action/approve_action
        never touch AttackNode.state, so a node stays AttackNodeState.KNOWN
        (its default, and the value every node on disk already has) until
        an Action against it actually runs here.

        When several nodes share TARGET (nothing prevents registering
        more than one), all of them move together. When several Actions
        target the same node over time, there is no aggregation across
        pending (PLANNED/APPROVED) ones -- only an executed Action's
        outcome is ever observed here, so the most recently *executed*
        action against a target simply overwrites that target's node
        state; an in-flight synchronous execute() call has no separately
        observable RUNNING state to persist."""
        for node in operation.nodes:
            if node.target == target:
                node.state = state

    def _execute_scan(self, action: Action, approval: Approval) -> RunRecord:
        """Run a SCAN action through the existing ScanRunner, the same
        engine `pownforge scan <plugin>` uses. The ExecutionRequest
        carries action_id/approval_id (refactor §18/P2 §9) since this
        run represents an approved AttackOperation Action, unlike a bare
        `pownforge scan` run outside any operation."""
        assert action.plugin is not None
        request = ExecutionRequest(
            target=action.target,
            plugin=action.plugin,
            options=action.options,
            action_id=action.id,
            approval_id=approval.id,
        )
        return ScanRunner(
            policy=self._policy,
            registry=self._registry,
            store=self._store,
            audit=self._audit,
            concurrency=self._concurrency,
        ).run_request(request)

    def _execute_manual_or_pivot(
        self,
        operation: AttackOperation,
        action: Action,
        *,
        manual_command: str | None,
        manual_output: str | None,
        manual_tool: str | None,
        manual_tool_version: str | None,
        manual_returncode: int,
    ) -> RunRecord:
        """Record-only: PownForge does not run action.name or anything
        else here -- manual_output must already be the transcript of
        what a human ran with an external tool (same invariant as
        `pownforge result import`; never a subprocess call)."""
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
                    f"pivot action '{action.id}' requires the operation to have "
                    "an engagement (set at `operation create --engagement`)"
                )
            incoming = attack_graph(operation).incoming_edges(action.target)
            if not incoming:
                raise OperationError(
                    f"pivot action '{action.id}' targets '{action.target}', but no "
                    "graph edge has it as a destination -- add one with "
                    "`operation add-edge` first"
                )
            via_target = incoming[-1].source
            engagement = operation.engagement
        return import_manual_run(
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
