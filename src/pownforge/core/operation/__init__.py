"""Facade package: `from pownforge.core.operation import X` keeps working for
every name this package re-exports below, exactly as when this was a single
operation.py file (refactor §5.1). Internal layout only -- callers should
import from `pownforge.core.operation`, not from a submodule directly, since
the submodule boundaries may still move.

Layout:
  model.py    -- AttackNode/AttackEdge/Action/Approval/AttackOperation/
                 ActionKind/ActionStatus/AttackPhase, OperationError
  store.py    -- AttackOperationStore (load/save/list, lock()/update())
  service.py  -- create_operation/add_node/add_edge/add_action
  approval.py -- approve_action
  runner.py   -- OperationRunner (execute())

The validation-primitive framework (ValidationPrimitive/PrimitiveContext/
PrimitiveRunner/ResourceRegistry) moved to the sibling core/primitives/
package; re-exported here too since `from pownforge.core.operation import
ValidationPrimitive` etc. predates that split.
"""

from __future__ import annotations

from pownforge.core.models import Capability
from pownforge.core.operation.approval import approve_action
from pownforge.core.operation.model import (
    Action,
    ActionKind,
    ActionStatus,
    Approval,
    AttackEdge,
    AttackNode,
    AttackOperation,
    AttackPhase,
    OperationError,
)
from pownforge.core.operation.runner import OperationRunner
from pownforge.core.operation.service import add_action, add_edge, add_node, create_operation
from pownforge.core.operation.store import AttackOperationStore
from pownforge.core.primitives import PrimitiveContext, PrimitiveRunner, ResourceRegistry, ValidationPrimitive
from pownforge.core.primitives.runner import validation_level_reaches

__all__ = [
    "Action",
    "ActionKind",
    "ActionStatus",
    "Approval",
    "AttackEdge",
    "AttackNode",
    "AttackOperation",
    "AttackOperationStore",
    "AttackPhase",
    "Capability",
    "OperationError",
    "OperationRunner",
    "PrimitiveContext",
    "PrimitiveRunner",
    "ResourceRegistry",
    "ValidationPrimitive",
    "add_action",
    "add_edge",
    "add_node",
    "approve_action",
    "create_operation",
    "validation_level_reaches",
]
