from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.evidence.hashing import sha256_text
from pownforge.evidence.store import EvidenceStore
from pownforge.web.app import create_app


def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        frontend_dist=tmp_path / "no-such-dist",
    )
    return TestClient(app)


def _seed_record(tmp_path: Path) -> RunRecord:
    store = EvidenceStore(tmp_path / "state" / "runs")
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    record = RunRecord(
        target="lab",
        plugin="network",
        evidence=evidence,
        output={"raw_stdout": "hi"},
        findings=[Finding(title="Open port 3000", severity="medium")],
    )
    store.save(record)
    return record


def test_review_finding_via_patch(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    finding_id = record.findings[0].finding_id

    resp = client.patch(
        f"/api/runs/{record.run_id}/findings/{finding_id}",
        json={"status": "confirmed"},
    )
    assert resp.status_code == 200
    assert resp.json()["findings"][0]["status"] == "confirmed"

    reloaded = client.get(f"/api/runs/{record.run_id}").json()
    assert reloaded["findings"][0]["status"] == "confirmed"


def test_review_unknown_finding_returns_404(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    resp = client.patch(
        f"/api/runs/{record.run_id}/findings/no-such-id",
        json={"status": "confirmed"},
    )
    assert resp.status_code == 404


def test_review_finding_on_unknown_run_returns_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.patch(
        "/api/runs/does-not-exist/findings/abc123",
        json={"status": "confirmed"},
    )
    assert resp.status_code == 404


def test_review_finding_rejects_invalid_status(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    finding_id = record.findings[0].finding_id
    resp = client.patch(
        f"/api/runs/{record.run_id}/findings/{finding_id}",
        json={"status": "very-bad"},
    )
    assert resp.status_code == 422


def test_list_and_get_run(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    assert [r["run_id"] for r in client.get("/api/runs").json()] == [record.run_id]
    assert client.get(f"/api/runs/{record.run_id}").json()["run_id"] == record.run_id
    assert client.get("/api/runs/does-not-exist").status_code == 404


def test_get_run_report_renders_markdown(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    resp = client.get(f"/api/runs/{record.run_id}/report")
    assert resp.status_code == 200
    assert f"Run {record.run_id}" in resp.json()["markdown"]


def test_get_run_report_renders_html_when_requested(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    resp = client.get(f"/api/runs/{record.run_id}/report?format=html")
    assert resp.status_code == 200
    body = resp.json()
    assert "markdown" not in body
    assert body["html"].startswith("<!doctype html>")
    assert f"Run {record.run_id}" in body["html"]


def test_verify_run_reports_mismatch_for_bogus_seeded_hashes(tmp_path: Path) -> None:
    # _seed_record uses placeholder hashes ("abc"/"def") that don't match the
    # seeded output, so this exercises the MISMATCH path end to end.
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    resp = client.get(f"/api/runs/{record.run_id}/verify")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["stdout"]["ok"] is False


def test_verify_run_ok_when_hashes_match(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "state" / "runs")
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256=sha256_text("hi"),
        stderr_sha256=sha256_text(""),
    )
    record = RunRecord(target="lab", plugin="network", evidence=evidence, output={"raw_stdout": "hi"})
    store.save(record)

    client = _client(tmp_path)
    resp = client.get(f"/api/runs/{record.run_id}/verify")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["stdout"]["ok"] is True
    assert body["stderr"]["ok"] is True


def test_verify_unknown_run_returns_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.get("/api/runs/does-not-exist/verify")
    assert resp.status_code == 404
