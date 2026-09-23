from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response

from pownforge.core.engagement_report import (
    EngagementReport,
    EngagementReportError,
    collect_engagement,
)
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.evidence.primitive_store import PrimitiveRunStore
from pownforge.evidence.store import EvidenceStore
from pownforge.reporting import engagement as engagement_report
from pownforge.web.deps import get_policy, get_primitive_store, get_store

router = APIRouter(tags=["reports"])


def _collect(
    target: str | None,
    engagement: str | None,
    store: EvidenceStore,
    primitive_store: PrimitiveRunStore,
    policy: ScopePolicy,
) -> EngagementReport:
    if target and engagement:
        raise HTTPException(status_code=400, detail="give either target or engagement, not both")
    engagement_targets = None
    scope_label = "all runs"
    if engagement:
        try:
            engagement_targets = policy.resolve_engagement(engagement).targets
        except PolicyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        scope_label = f"engagement: {engagement}"
    elif target:
        scope_label = f"target: {target}"
    try:
        return collect_engagement(
            store.list(),
            primitive_store.list(),
            target=target,
            engagement_targets=engagement_targets,
            scope_label=scope_label,
        )
    except EngagementReportError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/reports/engagement")
def get_engagement_report(
    target: str | None = None,
    engagement: str | None = None,
    format: str = "markdown",
    store: EvidenceStore = Depends(get_store),
    primitive_store: PrimitiveRunStore = Depends(get_primitive_store),
    policy: ScopePolicy = Depends(get_policy),
):
    report = _collect(target, engagement, store, primitive_store, policy)
    if format == "pdf":
        try:
            from pownforge.reporting import pdf as pdf_report
        except ImportError as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
        slug = engagement or target or "all"
        return Response(
            content=pdf_report.render_engagement(report),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="engagement-{slug}.pdf"'},
        )
    if format == "html":
        return {"html": engagement_report.render_html(report)}
    return {"markdown": engagement_report.render_markdown(report)}
