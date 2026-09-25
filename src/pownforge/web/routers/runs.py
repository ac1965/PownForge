from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from pydantic import BaseModel

from pownforge.ai.ollama import LLMAdapter
from pownforge.core.analysis import AnalysisError, run_analysis
from pownforge.core.findings import FindingNotFoundError, add_finding, review_finding
from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.models import (
    ChainVerification,
    EvidenceVerification,
    FindingStatus,
    KillChainPhase,
    RunRecord,
    Severity,
)
from pownforge.core.policy import PolicyError, SafetyError, ScopePolicy
from pownforge.core.settings import AppSettings, Language
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.reporting.html import render as render_html
from pownforge.reporting.markdown import render as render_markdown
from pownforge.web.deps import get_app_settings, get_audit_store, get_policy, get_store

router = APIRouter(tags=["runs"])


@router.get("/runs", response_model=list[RunRecord])
def list_runs(store: EvidenceStore = Depends(get_store)) -> list[RunRecord]:
    return store.list()


def _clean(value: str | None) -> str | None:
    return value or None


@router.post("/runs/import", response_model=RunRecord, status_code=201)
async def import_run(
    target: str = Form(...),
    command: str = Form(...),
    output: str = Form(...),
    tool: str | None = Form(None),
    tool_version: str | None = Form(None),
    returncode: int = Form(0),
    engagement: str | None = Form(None),
    via: str | None = Form(None),
    phase: str | None = Form(None),
    cve: list[str] = Form([]),
    artifacts: list[UploadFile] = File([]),
    store: EvidenceStore = Depends(get_store),
    policy: ScopePolicy = Depends(get_policy),
    audit: AuditStore = Depends(get_audit_store),
) -> RunRecord:
    """Record a manually-performed exploit step (multipart, with optional
    artifact uploads). PownForge never runs `command`; this is the web
    equivalent of `pownforge result import` -- same ScopePolicy authorization
    and evidence pipeline. See docs/handbook.md §13."""
    kill_chain_phase = None
    if _clean(phase):
        try:
            kill_chain_phase = KillChainPhase(phase)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"invalid phase '{phase}'") from exc

    tmp = Path(tempfile.mkdtemp(prefix="pownforge-import-"))
    try:
        artifact_paths: list[Path] = []
        for upload in artifacts:
            if not upload.filename:
                continue
            dest = tmp / Path(upload.filename).name
            with dest.open("wb") as fh:
                shutil.copyfileobj(upload.file, fh)
            artifact_paths.append(dest)
        try:
            record = import_manual_run(
                policy,
                store,
                target,
                command,
                output,
                tool=_clean(tool),
                tool_version=_clean(tool_version),
                returncode=returncode,
                audit=audit,
                engagement=_clean(engagement),
                via_target=_clean(via),
                kill_chain_phase=kill_chain_phase,
                artifacts=artifact_paths or None,
                cves=[c for c in cve if c.strip()] or None,
            )
        except SafetyError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except PolicyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return record


@router.get("/runs/verify-chain", response_model=ChainVerification)
def verify_runs_chain(store: EvidenceStore = Depends(get_store)) -> ChainVerification:
    """Whole-store hash-chain check across every run this workdir's
    EvidenceStore has ever saved (refactor v3 §6, web equivalent of
    `pownforge evidence verify-chain`). Declared before `/runs/{run_id}`
    so this literal path isn't swallowed by that dynamic one."""
    return store.verify_chain()


@router.get("/runs/{run_id}", response_model=RunRecord)
def get_run(run_id: str, store: EvidenceStore = Depends(get_store)) -> RunRecord:
    try:
        return store.load(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/runs/{run_id}/report")
def get_run_report(run_id: str, format: str = "markdown", store: EvidenceStore = Depends(get_store)):
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if format == "pdf":
        try:
            from pownforge.reporting import pdf as pdf_report
        except ImportError as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
        return Response(
            content=pdf_report.render(record),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{run_id}.pdf"'},
        )
    if format == "html":
        return {"html": render_html(record)}
    return {"markdown": render_markdown(record)}


@router.get("/runs/{run_id}/verify", response_model=EvidenceVerification)
def verify_run(run_id: str, store: EvidenceStore = Depends(get_store)) -> EvidenceVerification:
    try:
        return store.verify(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/runs/{run_id}/analyze", response_model=RunRecord)
def analyze_run(
    run_id: str,
    model: str | None = None,
    language: Language | None = None,
    store: EvidenceStore = Depends(get_store),
    settings: AppSettings = Depends(get_app_settings),
) -> RunRecord:
    adapter = LLMAdapter(model=model or settings.model)
    try:
        record, _ = run_analysis(store, run_id, adapter, language=language or settings.language)
    except AnalysisError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return record


class CveTagRequest(BaseModel):
    cves: list[str]
    remove: bool = False


@router.patch("/runs/{run_id}/cves", response_model=RunRecord)
def tag_run_cves(
    run_id: str, body: CveTagRequest, store: EvidenceStore = Depends(get_store)
) -> RunRecord:
    """Add or remove CVE tags on an existing run (scan or manual). Tags are
    correlation labels for the engagement report's CVE exposure matrix."""
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    cves = [c.strip() for c in body.cves if c.strip()]
    if not cves:
        raise HTTPException(status_code=400, detail="pass at least one cve")
    if body.remove:
        record.cves = [c for c in record.cves if c not in cves]
    else:
        for c in cves:
            if c not in record.cves:
                record.cves.append(c)
    store.save(record)
    return record


class FindingCreate(BaseModel):
    title: str
    severity: Severity = Severity.INFO
    detail: str = ""


@router.post("/runs/{run_id}/findings", response_model=RunRecord, status_code=201)
def add_run_finding(
    run_id: str, body: FindingCreate, store: EvidenceStore = Depends(get_store)
) -> RunRecord:
    """Attach a human-observed Finding (source="manual") to an existing run
    -- the web equivalent of `pownforge result add-finding`. Works on any
    run (a manual import or a tool scan alike), not just ones just
    imported. Starts at needs-review like every Finding regardless of
    source; a separate PATCH .../findings/{finding_id} call still confirms
    it (see core/findings.py::add_finding)."""
    try:
        record, _ = add_finding(store, run_id, body.title, body.severity, body.detail)
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return record


class FindingReview(BaseModel):
    status: FindingStatus


@router.patch("/runs/{run_id}/findings/{finding_id}", response_model=RunRecord)
def review_run_finding(
    run_id: str,
    finding_id: str,
    body: FindingReview,
    store: EvidenceStore = Depends(get_store),
) -> RunRecord:
    try:
        return review_finding(store, run_id, finding_id, body.status)
    except FindingNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
