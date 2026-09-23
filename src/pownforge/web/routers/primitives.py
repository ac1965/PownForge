from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from pownforge.core.models import PrimitiveDescriptor, PrimitiveRunRecord, ValidationLevel
from pownforge.core.operation import PrimitiveRunner
from pownforge.core.policy import PolicyError, SafetyError
from pownforge.evidence.primitive_store import PrimitiveRunStore
from pownforge.primitives.registry import PrimitiveError, build_primitive, list_primitives
from pownforge.reporting import primitive as primitive_report
from pownforge.web.deps import get_primitive_runner, get_primitive_store

router = APIRouter(tags=["primitives"])


class PrimitiveOptionInfo(BaseModel):
    name: str
    description: str
    required: bool


class PrimitiveInfo(BaseModel):
    descriptor: PrimitiveDescriptor
    options: list[PrimitiveOptionInfo]


class PrimitiveRunRequest(BaseModel):
    primitive: str
    target: str
    level: ValidationLevel = ValidationLevel.VALIDATION
    options: dict[str, str] = Field(default_factory=dict)


@router.get("/primitives", response_model=list[PrimitiveInfo])
def list_available_primitives() -> list[PrimitiveInfo]:
    return [
        PrimitiveInfo(
            descriptor=descriptor,
            options=[
                PrimitiveOptionInfo(name=o.name, description=o.description, required=o.required)
                for o in options
            ],
        )
        for descriptor, options in list_primitives()
    ]


@router.post("/primitives/run", response_model=PrimitiveRunRecord, status_code=201)
def run_primitive(
    body: PrimitiveRunRequest,
    runner: PrimitiveRunner = Depends(get_primitive_runner),
    store: PrimitiveRunStore = Depends(get_primitive_store),
) -> PrimitiveRunRecord:
    try:
        primitive = build_primitive(body.primitive, body.options)
    except PrimitiveError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        record = runner.run(primitive, body.target, body.level)
    except SafetyError as exc:
        # Beyond the SafetyPolicy envelope (already recorded to the audit log).
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except PolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    store.save(record)
    return record


@router.get("/primitive-runs", response_model=list[PrimitiveRunRecord])
def list_primitive_runs(store: PrimitiveRunStore = Depends(get_primitive_store)) -> list[PrimitiveRunRecord]:
    return store.list()


@router.get("/primitive-runs/{run_id}", response_model=PrimitiveRunRecord)
def get_primitive_run(
    run_id: str, store: PrimitiveRunStore = Depends(get_primitive_store)
) -> PrimitiveRunRecord:
    try:
        return store.load(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/primitive-runs/{run_id}/report")
def get_primitive_run_report(
    run_id: str, format: str = "markdown", store: PrimitiveRunStore = Depends(get_primitive_store)
):
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
            content=pdf_report.render_primitive(record),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{run_id}.pdf"'},
        )
    if format == "html":
        return {"html": primitive_report.render_html(record)}
    return {"markdown": primitive_report.render_markdown(record)}
