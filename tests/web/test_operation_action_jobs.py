from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.core.models import Target
from pownforge.core.registry import PluginRegistry
from pownforge.plugins.base import Plugin, PluginExecution
from pownforge.web.app import create_app
from pownforge.web.deps import get_registry


class EchoPlugin(Plugin):
    name = "echo"
    version = "0.0.1"
    description = "test double that echoes the target address"
    required_tool = "echo"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution) -> dict[str, Any]:
        return {"raw_stdout": raw_stdout, "raw_stderr": raw_stderr}


def _echo_registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(EchoPlugin())
    return registry


def _app(tmp_path: Path):
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )
    app.dependency_overrides[get_registry] = _echo_registry
    return app


def _prepared_scan_action(client: TestClient, action_id: str = "a1") -> None:
    client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})
    client.post("/api/operations", json={"name": "op-1"})
    client.post(
        "/api/operations/op-1/actions",
        json={"id": action_id, "name": "recon", "phase": "recon", "kind": "scan", "target": "lab", "plugin": "echo"},
    )
    client.post(f"/api/operations/op-1/actions/{action_id}/approve", json={"approved_by": "operator"})


def test_execute_async_streams_and_completes_scan_action(tmp_path: Path) -> None:
    # Must stay inside one `with` block -- see test_scans_routes.py's note on
    # why JobManager's background thread needs the same event loop alive.
    with TestClient(_app(tmp_path)) as client:
        _prepared_scan_action(client)

        resp = client.post("/api/operations/op-1/actions/a1/execute-async")
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        messages = []
        with client.websocket_connect(f"/api/ws/operations/jobs/{job_id}") as ws:
            while True:
                message = ws.receive_json()
                messages.append(message)
                if message["type"] in ("done", "error"):
                    break

        assert messages[-1]["type"] == "done"
        run_id = messages[-1]["run_id"]
        assert run_id is not None
        assert any(m["type"] == "line" and "127.0.0.1" in m["data"] for m in messages)

        status = client.get(f"/api/operations/jobs/{job_id}").json()
        assert status["status"] == "done"
        assert status["run_id"] == run_id
        assert status["returncode"] == 0

        operation = client.get("/api/operations/op-1").json()
        action = next(a for a in operation["actions"] if a["id"] == "a1")
        assert action["status"] == "completed"
        assert action["run_id"] == run_id


def test_execute_async_rejects_manual_action(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})
        client.post("/api/operations", json={"name": "op-1"})
        client.post(
            "/api/operations/op-1/actions",
            json={"id": "a1", "name": "manual foothold", "phase": "initial-access", "kind": "manual", "target": "lab"},
        )

        resp = client.post("/api/operations/op-1/actions/a1/execute-async")
        assert resp.status_code == 400
        assert "not 'scan'" in resp.json()["detail"]


def test_execute_async_unapproved_action_reports_error_over_ws(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})
        client.post("/api/operations", json={"name": "op-1"})
        client.post(
            "/api/operations/op-1/actions",
            json={"id": "a1", "name": "recon", "phase": "recon", "kind": "scan", "target": "lab", "plugin": "echo"},
        )
        # Deliberately not approved.

        resp = client.post("/api/operations/op-1/actions/a1/execute-async")
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        with client.websocket_connect(f"/api/ws/operations/jobs/{job_id}") as ws:
            message = ws.receive_json()
    assert message["type"] == "error"
    assert "must be approved" in message["message"]


def test_execute_async_unknown_operation_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/operations/nope/actions/a1/execute-async")
    assert resp.status_code == 404


def test_operation_job_status_unknown_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/operations/jobs/does-not-exist")
    assert resp.status_code == 404


def test_operation_job_ws_for_unknown_job_returns_error(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        with client.websocket_connect("/api/ws/operations/jobs/does-not-exist") as ws:
            message = ws.receive_json()
    assert message["type"] == "error"
