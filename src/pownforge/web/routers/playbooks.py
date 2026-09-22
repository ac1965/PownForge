from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from pownforge.core.models import Playbook
from pownforge.core.orchestrator import PlaybookError, list_playbooks, resolve_playbook
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.web.deps import (
    get_audit_store,
    get_playbooks_dir,
    get_policy,
    get_registry,
    get_store,
    get_job_manager,
)
from pownforge.web.jobs import JobManager

router = APIRouter(tags=["playbooks"])


class PlaybookRunRequest(BaseModel):
    target: str


class PlaybookRunCreated(BaseModel):
    job_id: str
    status: str


@router.get("/playbooks", response_model=list[Playbook])
def list_playbooks_route(playbooks_dir=Depends(get_playbooks_dir)) -> list[Playbook]:
    return list_playbooks(playbooks_dir)


@router.get("/playbooks/{name}", response_model=Playbook)
def get_playbook(name: str, playbooks_dir=Depends(get_playbooks_dir)) -> Playbook:
    try:
        return resolve_playbook(playbooks_dir, name)
    except PlaybookError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/playbooks/{name}/run", response_model=PlaybookRunCreated, status_code=202)
async def run_playbook_route(
    name: str,
    body: PlaybookRunRequest,
    playbooks_dir=Depends(get_playbooks_dir),
    policy: ScopePolicy = Depends(get_policy),
    registry: PluginRegistry = Depends(get_registry),
    store: EvidenceStore = Depends(get_store),
    audit: AuditStore = Depends(get_audit_store),
    jobs: JobManager = Depends(get_job_manager),
) -> PlaybookRunCreated:
    try:
        playbook = resolve_playbook(playbooks_dir, name)
    except PlaybookError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    job_id = jobs.submit_playbook(playbook, body.target, policy, registry, store, audit=audit)
    return PlaybookRunCreated(job_id=job_id, status="pending")


@router.websocket("/ws/playbooks/{job_id}")
async def playbook_live(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    jobs: JobManager = websocket.app.state.jobs
    job = jobs.get_playbook_job(job_id)
    if job is None:
        await websocket.send_json({"type": "error", "message": f"no job with id '{job_id}'"})
        await websocket.close()
        return

    try:
        while True:
            message = await job.queue.get()
            await websocket.send_json(message)
            if message["type"] == "done":
                break
    except WebSocketDisconnect:
        return
    await websocket.close()
