from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from pownforge.ai.ollama import OllamaAdapter
from pownforge.core.analysis import AnalysisError, run_analysis
from pownforge.core.findings import FindingNotFoundError, review_finding
from pownforge.core.models import EvidenceVerification, FindingStatus, RunRecord
from pownforge.evidence.store import EvidenceStore
from pownforge.reporting.markdown import render
from pownforge.web.deps import get_store

router = APIRouter(tags=["runs"])


@router.get("/runs", response_model=list[RunRecord])
def list_runs(store: EvidenceStore = Depends(get_store)) -> list[RunRecord]:
    return store.list()


@router.get("/runs/{run_id}", response_model=RunRecord)
def get_run(run_id: str, store: EvidenceStore = Depends(get_store)) -> RunRecord:
    try:
        return store.load(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/runs/{run_id}/report")
def get_run_report(run_id: str, store: EvidenceStore = Depends(get_store)) -> dict[str, str]:
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"markdown": render(record)}


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
    store: EvidenceStore = Depends(get_store),
) -> RunRecord:
    adapter = OllamaAdapter(model=model)
    try:
        record, _ = run_analysis(store, run_id, adapter)
    except AnalysisError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
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
