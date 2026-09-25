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
        settings=tmp_path / "settings.yaml",
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


def test_add_finding_via_post(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)

    resp = client.post(
        f"/api/runs/{record.run_id}/findings",
        json={"title": "Got a shell", "severity": "critical", "detail": "via CVE-2014-6271"},
    )
    assert resp.status_code == 201
    findings = resp.json()["findings"]
    assert len(findings) == 2  # kept the seeded tool-derived finding too
    added = next(f for f in findings if f["title"] == "Got a shell")
    assert added["severity"] == "critical"
    assert added["detail"] == "via CVE-2014-6271"
    assert added["source"] == "manual"
    assert added["status"] == "needs-review"  # still requires a separate review call

    reloaded = client.get(f"/api/runs/{record.run_id}").json()
    assert len(reloaded["findings"]) == 2


def test_add_finding_defaults_severity_to_info(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)

    resp = client.post(f"/api/runs/{record.run_id}/findings", json={"title": "Odd banner"})
    assert resp.status_code == 201
    added = next(f for f in resp.json()["findings"] if f["title"] == "Odd banner")
    assert added["severity"] == "info"


def test_add_finding_on_unknown_run_returns_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.post("/api/runs/does-not-exist/findings", json={"title": "x"})
    assert resp.status_code == 404


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


def test_get_run_report_renders_pdf_when_requested(tmp_path: Path) -> None:
    pytest.importorskip("reportlab")
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    resp = client.get(f"/api/runs/{record.run_id}/report?format=pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF-")
    assert record.run_id in resp.headers["content-disposition"]


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


def test_import_run_via_multipart_with_artifact(tmp_path: Path) -> None:
    client = _client(tmp_path)
    # register a target that allows the 'manual' plugin
    client.post(
        "/api/targets",
        json={"name": "lab", "kind": "host", "address": "127.0.0.1", "allowed_plugins": ["manual"]},
    )
    resp = client.post(
        "/api/runs/import",
        data={
            "target": "lab",
            "command": "msfconsole -x run",
            "output": "got shell",
            "tool": "msfconsole",
            "phase": "exploit",
            "cve": ["CVE-2021-44228"],
        },
        files=[("artifacts", ("session.txt", b"transcript", "text/plain"))],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["plugin"] == "manual"
    assert body["cves"] == ["CVE-2021-44228"]
    assert body["kill_chain_phase"] == "exploit"
    assert len(body["artifacts"]) == 1
    assert body["artifacts"][0]["sha256"]
    # persisted and retrievable
    assert client.get(f"/api/runs/{body['run_id']}").json()["cves"] == ["CVE-2021-44228"]


def test_import_run_unregistered_target_returns_409(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.post(
        "/api/runs/import",
        data={"target": "ghost", "command": "x", "output": "y"},
    )
    assert resp.status_code == 409


def test_import_run_invalid_phase_returns_422(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})
    resp = client.post(
        "/api/runs/import",
        data={"target": "lab", "command": "x", "output": "y", "phase": "not-a-phase"},
    )
    assert resp.status_code == 422


def test_tag_run_cves_add_and_remove(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    add = client.patch(f"/api/runs/{record.run_id}/cves", json={"cves": ["CVE-2021-44228", "CVE-2022-22965"]})
    assert add.status_code == 200
    assert add.json()["cves"] == ["CVE-2021-44228", "CVE-2022-22965"]
    rm = client.patch(f"/api/runs/{record.run_id}/cves", json={"cves": ["CVE-2021-44228"], "remove": True})
    assert rm.json()["cves"] == ["CVE-2022-22965"]


def test_tag_run_cves_unknown_run_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.patch("/api/runs/nope/cves", json={"cves": ["CVE-2021-44228"]})
    assert resp.status_code == 404


def test_tag_run_cves_empty_400(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    resp = client.patch(f"/api/runs/{record.run_id}/cves", json={"cves": []})
    assert resp.status_code == 400
