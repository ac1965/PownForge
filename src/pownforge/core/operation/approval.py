from __future__ import annotations

from pownforge.core.operation.model import ActionStatus, Approval, AttackOperation, OperationError, find_action
from pownforge.core.operation.store import AttackOperationStore


def approve_action(
    store: AttackOperationStore,
    operation_name: str,
    action_id: str,
    approved_by: str,
    note: str = "",
) -> AttackOperation:
    with store.lock(operation_name):
        operation = store.load(operation_name)
        action = find_action(operation, action_id)
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
