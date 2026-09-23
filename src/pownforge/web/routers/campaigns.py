from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from pownforge.core.attack_session import AttackSessionStore
from pownforge.core.models import Campaign
from pownforge.core.orchestrator import CampaignError, PlaybookError, list_campaigns, resolve_campaign, resolve_playbook
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.web.deps import (
    get_attack_sessions,
    get_audit_store,
    get_campaigns_dir,
    get_playbooks_dir,
    get_policy,
    get_registry,
    get_store,
    get_job_manager,
)
from pownforge.web.jobs import JobManager

router = APIRouter(tags=["campaigns"])


class CampaignRunRequest(BaseModel):
    session_name: str | None = None


class CampaignRunCreated(BaseModel):
    job_id: str
    status: str


@router.get("/campaigns", response_model=list[Campaign])
def list_campaigns_route(campaigns_dir=Depends(get_campaigns_dir)) -> list[Campaign]:
    return list_campaigns(campaigns_dir)


@router.get("/campaigns/{name}", response_model=Campaign)
def get_campaign(name: str, campaigns_dir=Depends(get_campaigns_dir)) -> Campaign:
    try:
        return resolve_campaign(campaigns_dir, name)
    except CampaignError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/campaigns/{name}/run", response_model=CampaignRunCreated, status_code=202)
async def run_campaign_route(
    name: str,
    body: CampaignRunRequest,
    campaigns_dir=Depends(get_campaigns_dir),
    playbooks_dir=Depends(get_playbooks_dir),
    policy: ScopePolicy = Depends(get_policy),
    registry: PluginRegistry = Depends(get_registry),
    store: EvidenceStore = Depends(get_store),
    sessions: AttackSessionStore = Depends(get_attack_sessions),
    audit: AuditStore = Depends(get_audit_store),
    jobs: JobManager = Depends(get_job_manager),
) -> CampaignRunCreated:
    try:
        campaign = resolve_campaign(campaigns_dir, name)
        playbook = resolve_playbook(playbooks_dir, campaign.playbook)
        engagement = policy.resolve_engagement(campaign.engagement)
    except (CampaignError, PlaybookError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not engagement.targets:
        raise HTTPException(status_code=400, detail=f"engagement '{engagement.name}' has no members")
    job_id = jobs.submit_campaign(
        campaign,
        playbook,
        engagement,
        policy,
        registry,
        store,
        sessions,
        audit=audit,
        session_name=body.session_name,
    )
    return CampaignRunCreated(job_id=job_id, status="pending")


@router.websocket("/ws/campaigns/{job_id}")
async def campaign_live(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    jobs: JobManager = websocket.app.state.jobs
    job = jobs.get_campaign_job(job_id)
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
