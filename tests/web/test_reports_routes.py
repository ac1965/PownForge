from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.core.models import (
    Claim,
    ConfidenceLevel,
    Evidence,
    Finding,
    PreconditionReport,
    PrimitiveEvidence,
    PrimitiveRunRecord,
    RunRecord,
    Severity,
    ValidationLevel,
)
from pownforge.evidence.primitive_store import PrimitiveRunStore
from pownforge.evidence.store import EvidenceStore
from pownforge.web.app import create_app

_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _app(tmp_path: Path):
    return create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )


def _seed(tmp_path: Path, target: str = "lab") -> None:
    ev = Evidence(command=["nmap", target], started_at=_T0, finished_at=_T0, returncode=0,
                  stdout_sha256="a", stderr_sha256="b")
    EvidenceStore(tmp_path / "state" / "runs").save(
        RunRecord(target=target, plugin="network", evidence=ev,
                  findings=[Finding(title="port", severity=Severity.LOW, source="tool")])
    )
    PrimitiveRunStore(tmp_path / "state" / "primitive_runs").save(
        PrimitiveRunRecord(
            primitive="http.oob-interaction", target=target,
            requested_level=ValidationLevel.VALIDATION, level_reached=ValidationLevel.VALIDATION,
            preconditions=PreconditionReport(),
            evidence=PrimitiveEvidence(
                target=target, primitive="http.oob-interaction",
                claims=[Claim(statement="oob", confidence=ConfidenceLevel.CONFIRMED)],
            ),
        )
    )


def test_engagement_report_markdown_merges_both(tmp_path: Path) -> None:
    _seed(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/reports/engagement", params={"target": "lab"})
    assert resp.status_code == 200
    md = resp.json()["markdown"]
    assert "**scan**" in md and "**primitive**" in md


def test_engagement_report_html_all_scope(tmp_path: Path) -> None:
    _seed(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/reports/engagement", params={"format": "html"})
    assert resp.status_code == 200
    assert resp.json()["html"].startswith("<!doctype html>")


def test_engagement_report_pdf(tmp_path: Path) -> None:
    pytest.importorskip("reportlab")
    _seed(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/reports/engagement", params={"target": "lab", "format": "pdf"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF-")


def test_engagement_report_empty_scope_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/reports/engagement", params={"target": "ghost"})
    assert resp.status_code == 404


def test_engagement_report_rejects_both_scopes(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/reports/engagement", params={"target": "a", "engagement": "b"})
    assert resp.status_code == 400


def test_engagement_report_unknown_engagement_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/reports/engagement", params={"engagement": "nope"})
    assert resp.status_code == 404
