from __future__ import annotations

import io

import pytest

from pownforge.core.models import (
    Claim,
    ConfidenceLevel,
    Finding,
    ManagedResource,
    Observation,
    Precondition,
    PreconditionReport,
    PreconditionStatus,
    PrimitiveEvidence,
    PrimitiveRunRecord,
    Provenance,
    ProvenanceKind,
    ResourceStatus,
    Severity,
    ValidationLevel,
)
from pownforge.reporting import primitive as primitive_report


def _observation(obs_id: str = "obs1") -> Observation:
    return Observation(
        id=obs_id,
        type="callback_received",
        detail="GET /tok from 127.0.0.1",
        provenance=Provenance(kind=ProvenanceKind.OBSERVED, primitive="http.oob-interaction"),
    )


def _record(**overrides) -> PrimitiveRunRecord:
    evidence = PrimitiveEvidence(
        target="lab",
        primitive="http.oob-interaction",
        observations=[_observation()],
        findings=[Finding(title="OOB interaction confirmed", severity=Severity.MEDIUM, source="tool")],
        claims=[
            Claim(statement="outbound request confirmed", confidence=ConfidenceLevel.CONFIRMED, supported_by=["obs1"])
        ],
    )
    defaults = dict(
        primitive="http.oob-interaction",
        category="oob-interaction",
        target="lab",
        requested_level=ValidationLevel.VALIDATION,
        level_reached=ValidationLevel.VALIDATION,
        preconditions=PreconditionReport(
            preconditions=[
                Precondition(id="P1", description="controllable input", status=PreconditionStatus.MET),
                Precondition(id="P2", description="url target", status=PreconditionStatus.UNKNOWN),
            ]
        ),
        evidence=evidence,
        resources=[ManagedResource(type="callback-listener", owner="run1", status=ResourceStatus.VERIFIED_ABSENT)],
    )
    defaults.update(overrides)
    return PrimitiveRunRecord(**defaults)


def test_markdown_covers_all_sections() -> None:
    md = primitive_report.render_markdown(_record())
    assert "# Primitive run" in md
    assert "http.oob-interaction" in md
    assert "✓ met" in md and "? unknown" in md
    assert "callback_received" in md
    assert "OOB interaction confirmed" in md
    assert "[confirmed]" in md and "obs1" in md
    assert "verified-absent" in md


def test_markdown_flags_residual_resources() -> None:
    record = _record(
        residual_resources=[ManagedResource(type="listener", owner="run1", status=ResourceStatus.CLEANUP_FAILED)]
    )
    md = primitive_report.render_markdown(record)
    assert "未検証のまま残っています" in md


def test_html_is_standalone_and_escapes() -> None:
    record = _record(target="<script>alert(1)</script>")
    html = primitive_report.render_html(record)
    assert html.startswith("<!doctype html>")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "前提条件" in html


def test_html_shows_precondition_status_classes() -> None:
    html = primitive_report.render_html(_record())
    assert 'class="met"' in html
    assert 'class="unknown"' in html


def test_pdf_renders_with_japanese_and_evidence() -> None:
    pytest.importorskip("reportlab")
    pypdf = pytest.importorskip("pypdf")
    from pownforge.reporting import pdf as pdf_report

    data = pdf_report.render_primitive(_record())
    assert data.startswith(b"%PDF-")
    text = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(data)).pages)
    assert "前提条件" in text
    assert "confirmed" in text
    assert "verified-absent" in text


def test_empty_evidence_is_handled() -> None:
    record = _record(evidence=None, resources=[])
    md = primitive_report.render_markdown(record)
    assert "観測はありません" in md
    assert "Findingはありません" in md
    html = primitive_report.render_html(record)
    assert "生成されたリソースはありません" in html
