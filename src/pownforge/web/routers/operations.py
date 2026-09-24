from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from pownforge.core.models import Capability
from pownforge.core.operation import (
    Action,
    ActionKind,
    AttackOperation,
    AttackPhase,
    AttackOperationStore,
    OperationError,
    OperationRunner,
    add_action,
    add_edge,
    add_node,
    approve_action,
    create_operation,
)
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.web.deps import get_operation_runner, get_operations, get_policy

router = APIRouter(tags=["operations"])


class OperationCreate(BaseModel):
    name: str
    objective: str = ""
    engagement: str | None = None


class NodeCreate(BaseModel):
    node_id: str
    target: str
    label: str = ""


class EdgeCreate(BaseModel):
    source: str
    destination: str
    capabilities: list[Capability] | None = None


class ActionCreate(BaseModel):
    """Deliberately excludes `status`/`run_id` -- Action has them (with
    defaults) so a new action always starts PLANNED with no run_id,
    regardless of what a caller sends, the same restriction the CLI's
    `operation add-action` (which only ever builds an Action from these
    same fields) already enforces structurally."""

    id: str
    name: str
    phase: AttackPhase
    kind: ActionKind = ActionKind.SCAN
    target: str
    plugin: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)
    prerequisites: list[str] = Field(default_factory=list)
    capabilities: list[Capability] = Field(default_factory=lambda: [Capability.READ_ONLY])
    requires: list[str] = Field(default_factory=list)
    provides: list[str] = Field(default_factory=list)


class ApprovalCreate(BaseModel):
    approved_by: str
    note: str = ""


class ExecuteRequest(BaseModel):
    command: str | None = None
    output: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    returncode: int = 0


@router.get("/operations", response_model=list[AttackOperation])
def list_operations(store: AttackOperationStore = Depends(get_operations)) -> list[AttackOperation]:
    return store.list()


@router.get("/operations/{name}", response_model=AttackOperation)
def get_operation(name: str, store: AttackOperationStore = Depends(get_operations)) -> AttackOperation:
    try:
        return store.load(name)
    except OperationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/operations", response_model=AttackOperation, status_code=201)
def add_operation(
    body: OperationCreate, store: AttackOperationStore = Depends(get_operations)
) -> AttackOperation:
    try:
        return create_operation(store, body.name, objective=body.objective, engagement=body.engagement)
    except OperationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/operations/{name}/nodes", response_model=AttackOperation, status_code=201)
def add_operation_node(
    name: str,
    body: NodeCreate,
    store: AttackOperationStore = Depends(get_operations),
    policy: ScopePolicy = Depends(get_policy),
) -> AttackOperation:
    try:
        return add_node(store, policy, name, body.node_id, body.target, label=body.label)
    except (OperationError, PolicyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operations/{name}/edges", response_model=AttackOperation, status_code=201)
def add_operation_edge(
    name: str,
    body: EdgeCreate,
    store: AttackOperationStore = Depends(get_operations),
    policy: ScopePolicy = Depends(get_policy),
) -> AttackOperation:
    try:
        return add_edge(store, policy, name, body.source, body.destination, body.capabilities)
    except (OperationError, PolicyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operations/{name}/actions", response_model=AttackOperation, status_code=201)
def add_operation_action(
    name: str,
    body: ActionCreate,
    store: AttackOperationStore = Depends(get_operations),
    policy: ScopePolicy = Depends(get_policy),
) -> AttackOperation:
    action = Action(**body.model_dump())
    try:
        return add_action(store, policy, name, action)
    except (OperationError, PolicyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operations/{name}/actions/{action_id}/approve", response_model=AttackOperation)
def approve_operation_action(
    name: str,
    action_id: str,
    body: ApprovalCreate,
    store: AttackOperationStore = Depends(get_operations),
) -> AttackOperation:
    try:
        return approve_action(store, name, action_id, body.approved_by, body.note)
    except OperationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/operations/{name}/actions/{action_id}/execute", response_model=AttackOperation)
def execute_operation_action(
    name: str,
    action_id: str,
    body: ExecuteRequest,
    store: AttackOperationStore = Depends(get_operations),
    runner: OperationRunner = Depends(get_operation_runner),
) -> AttackOperation:
    try:
        return store.update(
            name,
            lambda operation: runner.execute(
                operation,
                action_id,
                manual_command=body.command,
                manual_output=body.output,
                manual_tool=body.tool,
                manual_tool_version=body.tool_version,
                manual_returncode=body.returncode,
            ),
        )
    except OperationError as exc:
        # OperationRunner.execute() already wraps any PolicyError/RunnerError
        # it hits internally into OperationError -- see core/operation/runner.py.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
