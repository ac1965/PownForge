from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.core.models import Target
from pownforge.core.registry import PluginRegistry
from pownforge.plugins.base import Plugin
from pownforge.web.app import create_app
from pownforge.web.deps import get_registry


class EchoPlugin(Plugin):
    name = "echo"
    version = "0.0.1"
    description = "test double that echoes the target address"
    required_tool = "echo"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
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


def test_list_plugins_reflects_overridden_registry(tmp_path: Path) -> None:
    # A plain (non-context-managed) TestClient is fine here: this call has no
    # background thread writing back into the request's event loop afterward.
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/plugins")
    assert resp.status_code == 200
    assert [p["name"] for p in resp.json()] == ["echo"]


def test_scan_lifecycle_streams_and_creates_run(tmp_path: Path) -> None:
    # Must stay inside one `with` block: JobManager's background thread calls
    # back into the event loop that was running when the scan was submitted
    # (see web/jobs.py). Outside a `with`, TestClient tears that loop down
    # after each request, and the callback silently fails against a closed
    # loop — the WebSocket then hangs forever waiting on a queue nothing
    # can write to.
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})

        resp = client.post("/api/scans", json={"target": "lab", "plugin": "echo", "options": {}})
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        messages = []
        with client.websocket_connect(f"/api/ws/scans/{job_id}") as ws:
            while True:
                message = ws.receive_json()
                messages.append(message)
                if message["type"] in ("done", "error"):
                    break

        assert messages[-1]["type"] == "done"
        run_id = messages[-1]["run_id"]
        assert any(m["type"] == "line" and "127.0.0.1" in m["data"] for m in messages)

        status = client.get(f"/api/scans/{job_id}").json()
        assert status["status"] == "done"
        assert status["run_id"] == run_id

        runs = client.get("/api/runs").json()
        assert [r["run_id"] for r in runs] == [run_id]

        report = client.get(f"/api/runs/{run_id}/report").json()
        assert f"Run {run_id}" in report["markdown"]


def test_scan_against_unregistered_target_reports_error_over_ws(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/scans", json={"target": "nope", "plugin": "echo", "options": {}})
        job_id = resp.json()["job_id"]

        with client.websocket_connect(f"/api/ws/scans/{job_id}") as ws:
            message = ws.receive_json()
    assert message["type"] == "error"


def test_ws_for_unknown_job_returns_error(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        with client.websocket_connect("/api/ws/scans/does-not-exist") as ws:
            message = ws.receive_json()
    assert message["type"] == "error"
