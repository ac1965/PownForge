from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

import pytest

from pownforge.core.engagement_report import EngagementReportError, collect_engagement
from pownforge.core.models import (
    Claim,
    ConfidenceLevel,
    Evidence,
    Finding,
    FindingStatus,
    ManagedResource,
    Observation,
    PreconditionReport,
    PrimitiveEvidence,
    PrimitiveRunRecord,
    Provenance,
    ProvenanceKind,
    ResourceStatus,
    RunRecord,
    Severity,
    ValidationLevel,
)
from pownforge.reporting import engagement as engagement_report

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _run(target: str, when: datetime, *, confirmed: bool = False) -> RunRecord:
    ev = Evidence(
        command=["nmap", target],
        started_at=_T0,
        finished_at=_T0,
        returncode=0,
        stdout_sha256="a",
        stderr_sha256="b",
    )
    status = FindingStatus.CONFIRMED if confirmed else FindingStatus.NEEDS_REVIEW
    return RunRecord(
        target=target,
        plugin="network",
        created_at=when,
        evidence=ev,
        findings=[Finding(title="port", severity=Severity.MEDIUM, status=status, source="tool")],
    )


def _primitive(target: str, when: datetime, *, residual: bool = False, confirmed_claim: bool = True) -> PrimitiveRunRecord:
    obs = Observation(
        type="callback_received",
        detail="hit",
        provenance=Provenance(kind=ProvenanceKind.OBSERVED, primitive="http.oob-interaction"),
    )
    claims = (
        [Claim(statement="oob confirmed", confidence=ConfidenceLevel.CONFIRMED, supported_by=[obs.id])]
        if confirmed_claim
        else []
    )
    evidence = PrimitiveEvidence(
        target=target, primitive="http.oob-interaction", observations=[obs], claims=claims
    )
    return PrimitiveRunRecord(
        primitive="http.oob-interaction",
        category="oob-interaction",
        target=target,
        created_at=when,
        requested_level=ValidationLevel.VALIDATION,
        level_reached=ValidationLevel.VALIDATION,
        preconditions=PreconditionReport(),
        evidence=evidence,
        residual_resources=(
            [ManagedResource(type="listener", owner="r", status=ResourceStatus.CLEANUP_FAILED)]
            if residual
            else []
        ),
    )


def test_collect_filters_by_target() -> None:
    runs = [_run("lab", _T0), _run("other", _T0)]
    prims = [_primitive("lab", _T0), _primitive("other", _T0)]
    report = collect_engagement(runs, prims, target="lab", scope_label="target: lab")
    assert [r.target for r in report.runs] == ["lab"]
    assert [p.target for p in report.primitive_runs] == ["lab"]
    assert report.targets() == ["lab"]


def test_collect_filters_by_engagement_members() -> None:
    runs = [_run("a", _T0), _run("b", _T0), _run("c", _T0)]
    prims = [_primitive("a", _T0), _primitive("c", _T0)]
    report = collect_engagement(
        runs, prims, engagement_targets=["a", "b"], scope_label="engagement: e"
    )
    assert {r.target for r in report.runs} == {"a", "b"}
    assert {p.target for p in report.primitive_runs} == {"a"}


def test_collect_all_when_no_scope() -> None:
    report = collect_engagement([_run("a", _T0)], [_primitive("b", _T0)], scope_label="all runs")
    assert report.targets() == ["a", "b"]


def test_collect_raises_when_empty() -> None:
    with pytest.raises(EngagementReportError, match="no runs"):
        collect_engagement([], [], target="ghost", scope_label="target: ghost")


def test_markdown_merges_both_record_types_chronologically() -> None:
    runs = [_run("lab", _T0 + timedelta(minutes=2), confirmed=True)]
    prims = [_primitive("lab", _T0 + timedelta(minutes=1))]
    report = collect_engagement(runs, prims, target="lab", scope_label="target: lab")
    md = engagement_report.render_markdown(report)
    # primitive (t+1) appears before scan (t+2) in the timeline
    assert md.index("**primitive**") < md.index("**scan**")
    # both a confirmed scan finding and a confirmed primitive claim show up
    assert "scan finding" in md
    assert "primitive claim" in md
    assert "oob confirmed" in md


def test_markdown_surfaces_residual_resources() -> None:
    report = collect_engagement(
        [], [_primitive("lab", _T0, residual=True)], target="lab", scope_label="target: lab"
    )
    md = engagement_report.render_markdown(report)
    assert "残留リソース" in md
    assert "cleanup-failed" in md


def test_html_is_standalone_and_escapes() -> None:
    report = collect_engagement([_run("<x>", _T0)], [], scope_label="all runs")
    html = engagement_report.render_html(report)
    assert html.startswith("<!doctype html>")
    assert "<x>" not in html.split("<title>")[1]  # escaped in body
    assert "タイムライン" in html


def test_pdf_renders_with_japanese() -> None:
    pytest.importorskip("reportlab")
    pypdf = pytest.importorskip("pypdf")
    from pownforge.reporting import pdf as pdf_report

    report = collect_engagement(
        [_run("lab", _T0, confirmed=True)], [_primitive("lab", _T0)], target="lab", scope_label="target: lab"
    )
    data = pdf_report.render_engagement(report)
    assert data.startswith(b"%PDF-")
    text = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(data)).pages)
    assert "タイムライン" in text
    assert "oob confirmed" in text
