from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.core.models import Evidence, RunRecord
from pownforge.evidence.store import EvidenceStore
from pownforge.web.app import create_app


def _app(tmp_path: Path):
    return create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )


def _seed_run(tmp_path: Path, plugin: str = "network") -> str:
    store = EvidenceStore(tmp_path / "state" / "runs")
    evidence = Evidence(
        command=[plugin, "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    record = RunRecord(target="lab", plugin=plugin, evidence=evidence, output={})
    store.save(record)
    return record.run_id


def test_list_attack_sessions_empty_by_default(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/attack-sessions")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_and_get_attack_session(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post(
            "/api/attack-sessions", json={"name": "op-1", "description": "test", "engagement": None}
        )
        assert resp.status_code == 201
        assert resp.json()["stages"] == []

        got = client.get("/api/attack-sessions/op-1")
        assert got.status_code == 200
        assert got.json()["description"] == "test"


def test_create_duplicate_attack_session_returns_409(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/attack-sessions", json={"name": "op-1"})
        resp = client.post("/api/attack-sessions", json={"name": "op-1"})
    assert resp.status_code == 409


def test_get_unknown_attack_session_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/attack-sessions/nope")
    assert resp.status_code == 404


def test_add_stage_appends_and_persists(tmp_path: Path) -> None:
    run_id = _seed_run(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/attack-sessions", json={"name": "op-1"})
        resp = client.post(
            "/api/attack-sessions/op-1/stages", json={"run_id": run_id, "label": "initial recon"}
        )
        assert resp.status_code == 201
        assert resp.json()["stages"] == [{"run_id": run_id, "label": "initial recon"}]

        got = client.get("/api/attack-sessions/op-1")
        assert len(got.json()["stages"]) == 1


def test_add_stage_rejects_unknown_run_id(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/attack-sessions", json={"name": "op-1"})
        resp = client.post("/api/attack-sessions/op-1/stages", json={"run_id": "does-not-exist"})
    assert resp.status_code == 404


def test_add_stage_rejects_unknown_session(tmp_path: Path) -> None:
    run_id = _seed_run(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/attack-sessions/nope/stages", json={"run_id": run_id})
    assert resp.status_code == 404


def test_attack_session_report_markdown_and_html(tmp_path: Path) -> None:
    run_id = _seed_run(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/attack-sessions", json={"name": "op-1"})
        client.post("/api/attack-sessions/op-1/stages", json={"run_id": run_id, "label": "recon"})

        md = client.get("/api/attack-sessions/op-1/report")
        assert md.status_code == 200
        assert "markdown" in md.json()
        assert "Attack Session: op-1" in md.json()["markdown"]

        html = client.get("/api/attack-sessions/op-1/report?format=html")
        assert html.status_code == 200
        assert "<!doctype html>" in html.json()["html"]


def test_attack_session_report_unknown_session_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/attack-sessions/nope/report")
    assert resp.status_code == 404


def test_attack_session_report_pdf(tmp_path: Path) -> None:
    pytest.importorskip("reportlab")
    run_id = _seed_run(tmp_path)
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/attack-sessions", json={"name": "op-1"})
        client.post("/api/attack-sessions/op-1/stages", json={"run_id": run_id, "label": "recon"})

        resp = client.get("/api/attack-sessions/op-1/report?format=pdf")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content.startswith(b"%PDF-")
        assert "op-1" in resp.headers["content-disposition"]
