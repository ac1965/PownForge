from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from pownforge.ai.ollama import OllamaAdapter
from pownforge.core.analysis import AnalysisError, run_analysis
from pownforge.core.models import RunRecord
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
