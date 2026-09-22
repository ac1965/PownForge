from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.ai.ollama import OllamaAdapter, OllamaError
from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.evidence.store import EvidenceStore
from pownforge.web.app import create_app


def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        frontend_dist=tmp_path / "no-such-dist",
    )
    return TestClient(app)


def _seed_record(tmp_path: Path, target: str = "lab", created_at: str = "2026-01-01T00:00:00Z") -> RunRecord:
    store = EvidenceStore(tmp_path / "state" / "runs")
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at=created_at,
        finished_at=created_at,
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    record = RunRecord(
        target=target,
        plugin="network",
        created_at=created_at,
        evidence=evidence,
        output={"raw_stdout": "hi"},
        findings=[Finding(title="Open port 3000", severity="medium")],
    )
    store.save(record)
    return record


def test_create_walkthrough_by_run_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = _seed_record(tmp_path)
    monkeypatch.setattr(OllamaAdapter, "analyze", lambda self, prompt: "First we scanned the target.")
    client = _client(tmp_path)

    resp = client.post("/api/walkthroughs", json={"run_ids": [record.run_id]})
    assert resp.status_code == 200
    body = resp.json()
    assert "markdown" in body
    assert "First we scanned the target." in body["markdown"]
    assert body["suggestions"] == []  # plain-text stub response -> no structured suggestions


def test_create_walkthrough_returns_structured_suggestions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = _seed_record(tmp_path)
    response = json.dumps(
        {
            "narrative": "We scanned the target and found an open port.",
            "suggestions": [
                {"title": "Try nuclei next", "plugin": "nuclei", "rationale": "template-based follow-up"}
            ],
        }
    )
    monkeypatch.setattr(OllamaAdapter, "analyze", lambda self, prompt: response)
    client = _client(tmp_path)

    resp = client.post("/api/walkthroughs", json={"run_ids": [record.run_id]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["suggestions"] == [
        {
            "suggestion_id": body["suggestions"][0]["suggestion_id"],
            "title": "Try nuclei next",
            "plugin": "nuclei",
            "rationale": "template-based follow-up",
        }
    ]
    assert "We scanned the target and found an open port." in body["markdown"]


def test_create_walkthrough_html_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = _seed_record(tmp_path)
    monkeypatch.setattr(OllamaAdapter, "analyze", lambda self, prompt: "Narrative text.")
    client = _client(tmp_path)

    resp = client.post("/api/walkthroughs", json={"run_ids": [record.run_id], "format": "html"})
    assert resp.status_code == 200
    body = resp.json()
    assert "html" in body
    assert body["html"].startswith("<!doctype html>")


def test_create_walkthrough_by_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _seed_record(tmp_path, target="lab", created_at="2026-01-01T00:00:00Z")
    _seed_record(tmp_path, target="lab", created_at="2026-01-02T00:00:00Z")
    monkeypatch.setattr(OllamaAdapter, "analyze", lambda self, prompt: "Two steps happened.")
    client = _client(tmp_path)

    resp = client.post("/api/walkthroughs", json={"target": "lab"})
    assert resp.status_code == 200
    assert "Run 1" in resp.json()["markdown"]
    assert "Run 2" in resp.json()["markdown"]


def test_create_walkthrough_requires_run_ids_or_target(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.post("/api/walkthroughs", json={})
    assert resp.status_code == 400


def test_create_walkthrough_rejects_both_run_ids_and_target(tmp_path: Path) -> None:
    record = _seed_record(tmp_path)
    client = _client(tmp_path)
    resp = client.post("/api/walkthroughs", json={"run_ids": [record.run_id], "target": "lab"})
    assert resp.status_code == 400


def test_create_walkthrough_unknown_run_id_is_400(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.post("/api/walkthroughs", json={"run_ids": ["no-such-run"]})
    assert resp.status_code == 400


def test_create_walkthrough_llm_failure_is_502(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record = _seed_record(tmp_path)

    def raise_ollama_error(self, prompt: str) -> str:
        raise OllamaError("llm router not found")

    monkeypatch.setattr(OllamaAdapter, "analyze", raise_ollama_error)
    client = _client(tmp_path)
    resp = client.post("/api/walkthroughs", json={"run_ids": [record.run_id]})
    assert resp.status_code == 502
