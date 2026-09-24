from __future__ import annotations

from pownforge.core.identifiers import IdentifierError, validate_identifier
from pownforge.core.models import Capability
from pownforge.core.operation.graph import attack_graph
from pownforge.core.operation.model import Action, ActionKind, AttackEdge, AttackNode, AttackOperation, OperationError
from pownforge.core.operation.store import AttackOperationStore
from pownforge.core.policy import ScopePolicy


def create_operation(
    store: AttackOperationStore,
    name: str,
    objective: str = "",
    engagement: str | None = None,
) -> AttackOperation:
    try:
        validate_identifier(name, kind="operation")
    except IdentifierError as exc:
        raise OperationError(str(exc)) from exc
    with store.lock(name):
        try:
            store.load(name)
        except OperationError:
            pass
        else:
            raise OperationError(f"attack operation '{name}' already exists")
        operation = AttackOperation(
            name=name,
            objective=objective,
            engagement=engagement,
        )
        store.save(operation)
        return operation


def add_node(
    store: AttackOperationStore,
    policy: ScopePolicy,
    operation_name: str,
    node_id: str,
    target: str,
    label: str = "",
) -> AttackOperation:
    policy.resolve(target)
    with store.lock(operation_name):
        operation = store.load(operation_name)
        if any(node.id == node_id for node in operation.nodes):
            raise OperationError(f"node '{node_id}' already exists")
        operation.nodes.append(AttackNode(id=node_id, target=target, label=label))
        store.save(operation)
        return operation


def add_edge(
    store: AttackOperationStore,
    policy: ScopePolicy,
    operation_name: str,
    source: str,
    destination: str,
    capabilities: list[Capability] | None = None,
) -> AttackOperation:
    policy.resolve(source)
    policy.resolve(destination)
    if source == destination:
        raise OperationError("an attack graph edge cannot point to itself")
    with store.lock(operation_name):
        operation = store.load(operation_name)
        graph = attack_graph(operation)
        if not graph.has_target(source):
            raise OperationError(f"source target '{source}' is not a graph node")
        if not graph.has_target(destination):
            raise OperationError(f"destination target '{destination}' is not a graph node")
        edge = AttackEdge(
            source=source,
            destination=destination,
            capabilities=capabilities or [Capability.NETWORK_PIVOT],
        )
        if edge in operation.edges:
            raise OperationError("attack graph edge already exists")
        operation.edges.append(edge)
        store.save(operation)
        return operation


def add_action(
    store: AttackOperationStore,
    policy: ScopePolicy,
    operation_name: str,
    action: Action,
) -> AttackOperation:
    policy.resolve(action.target)
    with store.lock(operation_name):
        operation = store.load(operation_name)
        if any(existing.id == action.id for existing in operation.actions):
            raise OperationError(f"action '{action.id}' already exists")
        if action.kind == ActionKind.SCAN and not action.plugin:
            raise OperationError("scan actions require plugin")
        if action.kind != ActionKind.SCAN and action.plugin:
            raise OperationError("only scan actions may specify a plugin")
        operation.actions.append(action)
        store.save(operation)
        return operation
