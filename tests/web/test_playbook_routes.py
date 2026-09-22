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


def _write_playbook(playbooks_dir: Path, name: str, steps_yaml: str) -> None:
    playbooks_dir.mkdir(parents=True, exist_ok=True)
    (playbooks_dir / f"{name}.yaml").write_text(f"name: {name}\ndescription: test\nsteps:\n{steps_yaml}")


def _app(tmp_path: Path):
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
        playbooks_dir=tmp_path / "playbooks",
    )
    app.dependency_overrides[get_registry] = _echo_registry
    return app


def test_list_playbooks_empty_by_default(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/playbooks")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_and_get_playbook(tmp_path: Path) -> None:
    _write_playbook(tmp_path / "playbooks", "p", "  - plugin: echo\n")
    with TestClient(_app(tmp_path)) as client:
        listed = client.get("/api/playbooks").json()
        assert [p["name"] for p in listed] == ["p"]

        got = client.get("/api/playbooks/p").json()
        assert got["name"] == "p"
        assert got["steps"] == [{"plugin": "echo", "options": {}, "when": None}]


def test_get_unknown_playbook_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/playbooks/does-not-exist")
    assert resp.status_code == 404


def test_run_unknown_playbook_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/playbooks/does-not-exist/run", json={"target": "lab"})
    assert resp.status_code == 404


def test_playbook_run_lifecycle_streams_step_events_and_creates_runs(tmp_path: Path) -> None:
    _write_playbook(tmp_path / "playbooks", "two-echoes", "  - plugin: echo\n  - plugin: echo\n")
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})

        resp = client.post("/api/playbooks/two-echoes/run", json={"target": "lab"})
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        messages = []
        with client.websocket_connect(f"/api/ws/playbooks/{job_id}") as ws:
            while True:
                message = ws.receive_json()
                messages.append(message)
                if message["type"] == "done":
                    break

        starts = [m for m in messages if m["type"] == "step_start"]
        dones = [m for m in messages if m["type"] == "step_done"]
        assert [s["index"] for s in starts] == [1, 2]
        assert len(dones) == 2

        final = messages[-1]
        assert final["type"] == "done"
        assert len(final["run_ids"]) == 2

        runs = client.get("/api/runs").json()
        assert {r["run_id"] for r in runs} == set(final["run_ids"])


def test_playbook_run_reports_skipped_and_failed_steps_over_ws(tmp_path: Path) -> None:
    _write_playbook(
        tmp_path / "playbooks",
        "gated",
        "  - plugin: echo\n"
        "  - plugin: echo\n"
        "    when:\n      after_step: 1\n      min_severity: critical\n",
    )
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})

        resp = client.post("/api/playbooks/gated/run", json={"target": "lab"})
        job_id = resp.json()["job_id"]

        messages = []
        with client.websocket_connect(f"/api/ws/playbooks/{job_id}") as ws:
            while True:
                message = ws.receive_json()
                messages.append(message)
                if message["type"] == "done":
                    break

        skipped = [m for m in messages if m["type"] == "step_skipped"]
        assert len(skipped) == 1
        assert skipped[0]["index"] == 2


def test_ws_for_unknown_playbook_job_returns_error(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        with client.websocket_connect("/api/ws/playbooks/does-not-exist") as ws:
            message = ws.receive_json()
    assert message["type"] == "error"
