from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.core.models import Engagement, Target, TargetKind
from pownforge.core.policy import ScopePolicy
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


def _write_campaign(campaigns_dir: Path, name: str, engagement: str, playbook: str) -> None:
    campaigns_dir.mkdir(parents=True, exist_ok=True)
    (campaigns_dir / f"{name}.yaml").write_text(
        f"name: {name}\ndescription: test\nengagement: {engagement}\nplaybook: {playbook}\n"
    )


def _seed_scope(config: Path, targets: list[Target], engagements: list[Engagement]) -> None:
    policy = ScopePolicy(targets={})
    for target in targets:
        policy.add_target(target)
    for engagement in engagements:
        policy.add_engagement(engagement)
    policy.save(config)


def _app(tmp_path: Path):
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
        playbooks_dir=tmp_path / "playbooks",
        campaigns_dir=tmp_path / "campaigns",
    )
    app.dependency_overrides[get_registry] = _echo_registry
    return app


def test_list_campaigns_empty_by_default(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/campaigns")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_and_get_campaign(tmp_path: Path) -> None:
    _write_campaign(tmp_path / "campaigns", "c", "sweep", "p")
    with TestClient(_app(tmp_path)) as client:
        listed = client.get("/api/campaigns").json()
        assert [c["name"] for c in listed] == ["c"]

        got = client.get("/api/campaigns/c").json()
        assert got["engagement"] == "sweep"
        assert got["playbook"] == "p"


def test_get_unknown_campaign_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/campaigns/does-not-exist")
    assert resp.status_code == 404


def test_run_unknown_campaign_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/campaigns/does-not-exist/run", json={})
    assert resp.status_code == 404


def test_run_campaign_with_unregistered_engagement_returns_400(tmp_path: Path) -> None:
    _write_campaign(tmp_path / "campaigns", "c", "does-not-exist", "p")
    _write_playbook(tmp_path / "playbooks", "p", "  - plugin: echo\n")
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/campaigns/c/run", json={})
    assert resp.status_code == 400


def test_list_engagements(tmp_path: Path) -> None:
    _seed_scope(
        tmp_path / "targets.yaml",
        targets=[
            Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"),
            Target(name="lab-2", kind=TargetKind.HOST, address="127.0.0.2"),
        ],
        engagements=[Engagement(name="sweep", targets=["lab", "lab-2"])],
    )
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/engagements")
    assert resp.status_code == 200
    assert resp.json() == [{"name": "sweep", "targets": ["lab", "lab-2"], "notes": None}]


def test_campaign_run_lifecycle_streams_events_and_creates_attack_session(tmp_path: Path) -> None:
    _seed_scope(
        tmp_path / "targets.yaml",
        targets=[
            Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"),
            Target(name="lab-2", kind=TargetKind.HOST, address="127.0.0.2"),
        ],
        engagements=[Engagement(name="sweep", targets=["lab", "lab-2"])],
    )
    _write_playbook(tmp_path / "playbooks", "two-echoes", "  - plugin: echo\n  - plugin: echo\n")
    _write_campaign(tmp_path / "campaigns", "c", "sweep", "two-echoes")

    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/campaigns/c/run", json={"session_name": "my-sweep"})
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        messages = []
        with client.websocket_connect(f"/api/ws/campaigns/{job_id}") as ws:
            while True:
                message = ws.receive_json()
                messages.append(message)
                if message["type"] == "done":
                    break

        starts = [m for m in messages if m["type"] == "step_start"]
        dones = [m for m in messages if m["type"] == "step_done"]
        assert {s["target"] for s in starts} == {"lab", "lab-2"}
        assert len(dones) == 4  # 2 targets x 2 steps

        final = messages[-1]
        assert final["type"] == "done"
        assert final["session_name"] == "my-sweep"
        assert final["stage_count"] == 4

        session = client.get("/api/attack-sessions/my-sweep").json()
        assert session["engagement"] == "sweep"
        assert len(session["stages"]) == 4
        assert {s["label"] for s in session["stages"]} == {"lab: echo", "lab-2: echo"}


def test_ws_for_unknown_campaign_job_returns_error(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        with client.websocket_connect("/api/ws/campaigns/does-not-exist") as ws:
            message = ws.receive_json()
    assert message["type"] == "error"
