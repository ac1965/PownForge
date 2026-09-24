from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.web.app import create_app


def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )
    return TestClient(app)


def test_scan_against_unregistered_target_is_recorded_in_audit(tmp_path: Path) -> None:
    # Must be `with ... as client:` (a single persistent portal/event loop
    # for the whole test), not a bare TestClient(app) -- see the other
    # websocket tests (tests/web/test_scans_routes.py,
    # tests/web/test_playbook_routes.py) for the same pattern. Without it,
    # each call gets its own throwaway event loop (starlette's
    # TestClient._portal_factory), so the background job thread can end up
    # scheduling its `job.queue` message onto the loop that served the
    # POST /api/scans call after that loop has already been torn down --
    # an intermittent hang here (the websocket's ws.receive_json() below
    # never returns) rather than a deterministic failure, since it only
    # happens when the background thread is slower than the request.
    with _client(tmp_path) as client:
        resp = client.post("/api/scans", json={"target": "nope", "plugin": "network", "options": {}})
        job_id = resp.json()["job_id"]
        with client.websocket_connect(f"/api/ws/scans/{job_id}") as ws:
            message = ws.receive_json()
        assert message["type"] == "error"

        violations = client.get("/api/audit").json()
        assert len(violations) == 1
        assert violations[0]["target"] == "nope"
        assert violations[0]["plugin"] == "network"


def test_get_unknown_violation_returns_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.get("/api/audit/no-such-id")
    assert resp.status_code == 404


def test_list_audit_empty_by_default(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/api/audit").json() == []
