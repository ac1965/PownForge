from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, WebSocket, WebSocketDisconnect
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
from pownforge.evidence.store import EvidenceStore
from pownforge.reporting.operation import render_html, render_markdown
from pownforge.web.deps import get_job_manager, get_operation_runner, get_operations, get_policy, get_store
from pownforge.web.jobs import JobManager

router = APIRouter(tags=["operations"])


class OperationCreate(BaseModel):
    name: str
    objective: str = ""
    engagement: str | None = None


class NodeCreate(BaseModel):
    node_id: str
    target: str
    label: str = ""
    attack_technique_ids: list[str] = Field(default_factory=list)


class EdgeCreate(BaseModel):
    source: str
    destination: str
    capabilities: list[Capability] | None = None
    attack_technique_ids: list[str] = Field(default_factory=list)


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
    attack_technique_ids: list[str] = Field(default_factory=list)


class ApprovalCreate(BaseModel):
    approved_by: str
    note: str = ""


class ExecuteRequest(BaseModel):
    command: str | None = None
    output: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    returncode: int = 0


class OperationActionJobCreated(BaseModel):
    job_id: str
    status: str


class OperationActionJobStatus(BaseModel):
    job_id: str
    status: str
    run_id: str | None = None
    returncode: int | None = None
    error: str | None = None


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
        return add_node(
            store, policy, name, body.node_id, body.target, label=body.label,
            attack_technique_ids=body.attack_technique_ids,
        )
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
        return add_edge(
            store, policy, name, body.source, body.destination, body.capabilities,
            attack_technique_ids=body.attack_technique_ids,
        )
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


@router.post(
    "/operations/{name}/actions/{action_id}/execute-async",
    response_model=OperationActionJobCreated,
    status_code=202,
)
async def execute_operation_action_async(
    name: str,
    action_id: str,
    store: AttackOperationStore = Depends(get_operations),
    evidence: EvidenceStore = Depends(get_store),
    runner: OperationRunner = Depends(get_operation_runner),
    jobs: JobManager = Depends(get_job_manager),
) -> OperationActionJobCreated:
    """Run a SCAN-kind Action in the background and stream its output over
    `/ws/operations/jobs/{job_id}`, the same live-progress pattern
    `POST /scans` already gives a bare `pownforge scan` (refactor v3 §1
    -- the synchronous `.../execute` above blocks the request until the
    tool exits, with no progress in between). MANUAL/PIVOT actions never
    invoke a subprocess (PownForge only records evidence a human already
    produced) and have nothing to stream, so they stay on the synchronous
    endpoint -- rejected here with 400 rather than silently queued."""
    try:
        operation = store.load(name)
    except OperationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    action = next((a for a in operation.actions if a.id == action_id), None)
    if action is None:
        raise HTTPException(status_code=404, detail=f"no action named '{action_id}'")
    if action.kind != ActionKind.SCAN:
        raise HTTPException(
            status_code=400,
            detail=f"action '{action_id}' is kind '{action.kind.value}', not 'scan' -- "
            "use the synchronous .../execute endpoint for manual/pivot actions",
        )
    job_id = jobs.submit_operation_action(store, evidence, name, action_id, runner)
    return OperationActionJobCreated(job_id=job_id, status="pending")


@router.get("/operations/jobs/{job_id}", response_model=OperationActionJobStatus)
def get_operation_action_job_status(
    job_id: str, jobs: JobManager = Depends(get_job_manager)
) -> OperationActionJobStatus:
    job = jobs.get_operation_action_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"no job with id '{job_id}'")
    return OperationActionJobStatus(
        job_id=job.job_id, status=job.status, run_id=job.run_id, returncode=job.returncode, error=job.error
    )


@router.websocket("/ws/operations/jobs/{job_id}")
async def operation_action_job_live(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    jobs: JobManager = websocket.app.state.jobs
    job = jobs.get_operation_action_job(job_id)
    if job is None:
        await websocket.send_json({"type": "error", "message": f"no job with id '{job_id}'"})
        await websocket.close()
        return

    try:
        while True:
            message = await job.queue.get()
            await websocket.send_json(message)
            if message["type"] in ("done", "error"):
                break
    except WebSocketDisconnect:
        return
    await websocket.close()


@router.get("/operations/{name}/report")
def get_operation_report(
    name: str,
    format: str = "markdown",
    store: AttackOperationStore = Depends(get_operations),
    evidence: EvidenceStore = Depends(get_store),
):
    try:
        operation = store.load(name)
    except OperationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    records: dict[str, Any] = {}
    for action in operation.actions:
        if action.run_id and action.run_id not in records:
            try:
                records[action.run_id] = evidence.load(action.run_id)
            except FileNotFoundError:
                pass
    if format == "pdf":
        try:
            from pownforge.reporting import pdf as pdf_report
        except ImportError as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
        return Response(
            content=pdf_report.render_operation(operation, records),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="operation-{name}.pdf"'},
        )
    if format == "html":
        return {"html": render_html(operation, records)}
    return {"markdown": render_markdown(operation, records)}
