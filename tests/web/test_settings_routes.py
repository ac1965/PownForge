from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.ai.ollama import OllamaAdapter
from pownforge.core.settings import load_settings
from pownforge.web.app import create_app


def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )
    return TestClient(app)


def test_get_settings_defaults_when_unset(tmp_path: Path) -> None:
    resp = _client(tmp_path).get("/api/settings")
    assert resp.status_code == 200
    assert resp.json() == {"model": None, "language": "ja"}


def test_put_settings_persists_to_disk(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.put("/api/settings", json={"model": "claude-haiku-4.5", "language": "en"})
    assert resp.status_code == 200
    assert resp.json() == {"model": "claude-haiku-4.5", "language": "en"}

    reloaded = load_settings(tmp_path / "settings.yaml")
    assert reloaded.model == "claude-haiku-4.5"
    assert reloaded.language.value == "en"

    # A second GET reflects the write immediately (reloaded from disk).
    resp = client.get("/api/settings")
    assert resp.json() == {"model": "claude-haiku-4.5", "language": "en"}


def test_walkthrough_uses_saved_settings_as_default_model_and_language(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pownforge.evidence.store import EvidenceStore
    from pownforge.core.models import Evidence, RunRecord

    store = EvidenceStore(tmp_path / "state" / "runs")
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:00Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    record = RunRecord(target="lab", plugin="network", evidence=evidence, output={"raw_stdout": "hi"})
    store.save(record)

    client = _client(tmp_path)
    client.put("/api/settings", json={"model": "claude-haiku-4.5", "language": "en"})

    seen = {}

    def fake_analyze(self, prompt: str) -> str:
        seen["model"] = self._model
        seen["prompt"] = prompt
        return "narrative"

    monkeypatch.setattr(OllamaAdapter, "analyze", fake_analyze)

    resp = client.post("/api/walkthroughs", json={"run_ids": [record.run_id]})
    assert resp.status_code == 200
    assert seen["model"] == "claude-haiku-4.5"
    assert "entirely in English" in seen["prompt"]
