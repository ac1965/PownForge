from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from pownforge.core.attack_session import AttackSessionError, AttackSessionStore, add_stage, create_attack_session
from pownforge.core.models import AttackSession
from pownforge.evidence.store import EvidenceStore
from pownforge.reporting.attack_session import render_html, render_markdown
from pownforge.web.deps import get_attack_sessions, get_store

router = APIRouter(tags=["attack-sessions"])


class AttackSessionCreate(BaseModel):
    name: str
    description: str = ""
    engagement: str | None = None


class AttackSessionStageCreate(BaseModel):
    run_id: str
    label: str = ""


@router.get("/attack-sessions", response_model=list[AttackSession])
def list_attack_sessions(store: AttackSessionStore = Depends(get_attack_sessions)) -> list[AttackSession]:
    return store.list()


@router.get("/attack-sessions/{name}", response_model=AttackSession)
def get_attack_session(name: str, store: AttackSessionStore = Depends(get_attack_sessions)) -> AttackSession:
    try:
        return store.load(name)
    except AttackSessionError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/attack-sessions", response_model=AttackSession, status_code=201)
def add_attack_session(
    body: AttackSessionCreate, store: AttackSessionStore = Depends(get_attack_sessions)
) -> AttackSession:
    try:
        return create_attack_session(
            store, body.name, description=body.description, engagement=body.engagement
        )
    except AttackSessionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/attack-sessions/{name}/stages", response_model=AttackSession, status_code=201)
def add_attack_session_stage(
    name: str,
    body: AttackSessionStageCreate,
    store: AttackSessionStore = Depends(get_attack_sessions),
    evidence: EvidenceStore = Depends(get_store),
) -> AttackSession:
    try:
        return add_stage(store, evidence, name, body.run_id, label=body.label)
    except AttackSessionError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/attack-sessions/{name}/report")
def get_attack_session_report(
    name: str,
    format: str = "markdown",
    store: AttackSessionStore = Depends(get_attack_sessions),
    evidence: EvidenceStore = Depends(get_store),
):
    try:
        session = store.load(name)
    except AttackSessionError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        records = [evidence.load(stage.run_id) for stage in session.stages]
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if format == "pdf":
        try:
            from pownforge.reporting import pdf as pdf_report
        except ImportError as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
        return Response(
            content=pdf_report.render_attack_session(session, records),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="attack-session-{name}.pdf"'},
        )
    if format == "html":
        return {"html": render_html(session, records)}
    return {"markdown": render_markdown(session, records)}
