from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from pownforge.core.models import PluginMetadata
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import ScanRunner
from pownforge.web.deps import get_job_manager, get_registry, get_runner
from pownforge.web.jobs import JobManager

router = APIRouter(tags=["scans"])


class ScanRequest(BaseModel):
    target: str
    plugin: str
    options: dict[str, str] = {}


class ScanCreated(BaseModel):
    job_id: str
    status: str


class ScanStatus(BaseModel):
    job_id: str
    status: str
    run_id: str | None = None
    error: str | None = None


@router.get("/plugins", response_model=list[PluginMetadata])
def list_plugins(registry: PluginRegistry = Depends(get_registry)) -> list[PluginMetadata]:
    return [plugin.metadata() for plugin in registry.list()]


@router.post("/scans", response_model=ScanCreated, status_code=202)
async def create_scan(
    body: ScanRequest,
    runner: ScanRunner = Depends(get_runner),
    jobs: JobManager = Depends(get_job_manager),
) -> ScanCreated:
    job_id = jobs.submit(runner, body.target, body.plugin, body.options)
    return ScanCreated(job_id=job_id, status="pending")


@router.get("/scans/{job_id}", response_model=ScanStatus)
def get_scan(job_id: str, jobs: JobManager = Depends(get_job_manager)) -> ScanStatus:
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"no job with id '{job_id}'")
    return ScanStatus(job_id=job.job_id, status=job.status, run_id=job.run_id, error=job.error)


@router.websocket("/ws/scans/{job_id}")
async def scan_live(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    jobs: JobManager = websocket.app.state.jobs
    job = jobs.get(job_id)
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
