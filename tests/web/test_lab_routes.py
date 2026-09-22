from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.core.lab import LabManager
from pownforge.web.app import create_app
from pownforge.web.deps import get_lab_manager


@dataclass
class FakeResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class FakeDocker:
    def __init__(self) -> None:
        self.network_exists = True
        self.ps_output = ""

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "network"] and command[2] == "inspect":
            return FakeResult(returncode=0 if self.network_exists else 1)  # type: ignore[return-value]
        if command[:3] == ["docker", "network", "create"]:
            self.network_exists = True
            return FakeResult(returncode=0)  # type: ignore[return-value]
        if command[:2] == ["docker", "run"]:
            return FakeResult(returncode=0, stdout="containerid\n")  # type: ignore[return-value]
        if command[:2] == ["docker", "rm"]:
            return FakeResult(returncode=0)  # type: ignore[return-value]
        if command[:2] == ["docker", "ps"]:
            return FakeResult(returncode=0, stdout=self.ps_output)  # type: ignore[return-value]
        raise AssertionError(f"unexpected docker command: {command}")


def _client(tmp_path: Path, docker: FakeDocker) -> TestClient:
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )
    app.dependency_overrides[get_lab_manager] = lambda: LabManager(network="test-lab", runner=docker)
    return TestClient(app)


def test_add_lab_host_registers_target(tmp_path: Path) -> None:
    docker = FakeDocker()
    client = _client(tmp_path, docker)

    resp = client.post(
        "/api/lab",
        json={"name": "lab-web", "image": "vulnerable/image", "kind": "url", "port": 3000},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["host"]["name"] == "lab-web"
    assert body["target"]["address"] == "http://lab-web:3000"

    names = [t["name"] for t in client.get("/api/targets").json()]
    assert names == ["lab-web"]


def test_add_lab_host_url_kind_without_port_returns_422(tmp_path: Path) -> None:
    docker = FakeDocker()
    client = _client(tmp_path, docker)
    resp = client.post("/api/lab", json={"name": "lab-web", "image": "vulnerable/image", "kind": "url"})
    assert resp.status_code == 422


def test_list_lab_hosts(tmp_path: Path) -> None:
    docker = FakeDocker()
    docker.ps_output = json.dumps({"Names": "lab-web", "Image": "vulnerable/image", "Status": "Up"})
    client = _client(tmp_path, docker)
    resp = client.get("/api/lab")
    assert resp.status_code == 200
    assert resp.json() == [{"name": "lab-web", "image": "vulnerable/image", "status": "Up"}]


def test_remove_lab_host_with_purge(tmp_path: Path) -> None:
    docker = FakeDocker()
    client = _client(tmp_path, docker)
    client.post("/api/lab", json={"name": "lab-web", "image": "vulnerable/image"})
    resp = client.delete("/api/lab/lab-web", params={"purge": "true"})
    assert resp.status_code == 204
    assert client.get("/api/targets").json() == []
