from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

import pownforge.core.lab as lab
from pownforge.core.policy import ScopePolicy
from pownforge.web.app import create_app


@dataclass
class FakeResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class FakeCompose:
    def __init__(self, ps_json: str = "[]") -> None:
        self.ps_json = ps_json

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        verb = command[4] if len(command) > 4 else ""
        if verb == "ps":
            return FakeResult(returncode=0, stdout=self.ps_json)  # type: ignore[return-value]
        return FakeResult(returncode=0)  # type: ignore[return-value]


def _checkout(tmp_path: Path) -> Path:
    root = tmp_path / "vulhub"
    (root / "log4j" / "CVE-2021-44228").mkdir(parents=True)
    (root / "log4j" / "CVE-2021-44228" / "docker-compose.yml").write_text("services: {}\n")
    return root


def _app(tmp_path: Path):
    return create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
        vulhub_dir=_checkout(tmp_path),
    )


@pytest.fixture(autouse=True)
def _fake_compose(monkeypatch):
    ps = json.dumps([{"Service": "web", "Publishers": [{"PublishedPort": 8080, "TargetPort": 8080}]}])
    fake = FakeCompose(ps)
    original = lab.VulhubProvider.__init__

    def patched(self, root, runner=fake):  # noqa: ANN001
        original(self, root, runner=fake)

    monkeypatch.setattr(lab.VulhubProvider, "__init__", patched)


def test_list_scenarios(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/lab/provider/scenarios")
    assert resp.status_code == 200
    assert [s["id"] for s in resp.json()] == ["log4j/CVE-2021-44228"]


def test_status_uses_query_param_for_slashed_id(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/lab/provider/status", params={"scenario": "log4j/CVE-2021-44228"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["running"] is True
    assert body["published_ports"][0]["host_port"] == 8080


def test_start_with_register_adds_scoped_target(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with TestClient(app) as client:
        resp = client.post(
            "/api/lab/provider/start", json={"scenario": "log4j/CVE-2021-44228", "register_target": True}
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["registered_target"]["address"] == "http://127.0.0.1:8080"
    assert "isolated lab host" in body["warning"]
    policy = ScopePolicy.load(tmp_path / "targets.yaml")
    assert policy.resolve("vulhub-log4j-cve-2021-44228").address == "http://127.0.0.1:8080"


def test_cleanup_with_purge_removes_target(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with TestClient(app) as client:
        client.post(
            "/api/lab/provider/start", json={"scenario": "log4j/CVE-2021-44228", "register_target": True}
        )
        assert "vulhub-log4j-cve-2021-44228" in ScopePolicy.load(tmp_path / "targets.yaml")._targets  # noqa: SLF001
        resp = client.post(
            "/api/lab/provider/cleanup", json={"scenario": "log4j/CVE-2021-44228", "purge": True}
        )
    assert resp.status_code == 204
    assert "vulhub-log4j-cve-2021-44228" not in ScopePolicy.load(tmp_path / "targets.yaml")._targets  # noqa: SLF001


def test_stop_returns_204(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/lab/provider/stop", json={"scenario": "log4j/CVE-2021-44228"})
    assert resp.status_code == 204
