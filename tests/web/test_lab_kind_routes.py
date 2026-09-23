from __future__ import annotations

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


class FakeKind:
    """Stands in for the `kind` CLI. Records created clusters and returns a
    canned internal kubeconfig for `get kubeconfig`."""

    def __init__(self) -> None:
        self.clusters: list[str] = []

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["kind", "create", "cluster"]:
            self.clusters.append(command[command.index("--name") + 1])
            return FakeResult()  # type: ignore[return-value]
        if command[:3] == ["kind", "get", "kubeconfig"]:
            name = command[command.index("--name") + 1]
            return FakeResult(stdout=f"server: https://{name}-control-plane:6443\n")  # type: ignore[return-value]
        if command[:3] == ["kind", "delete", "cluster"]:
            return FakeResult()  # type: ignore[return-value]
        if command[:3] == ["kind", "get", "clusters"]:
            return FakeResult(stdout="".join(f"{c}\n" for c in self.clusters))  # type: ignore[return-value]
        raise AssertionError(f"unexpected kind command: {command}")


@pytest.fixture(autouse=True)
def _fake_kind(monkeypatch):
    fake = FakeKind()
    original = lab.KindClusterManager.__init__

    def patched(self, runner=fake):  # noqa: ANN001
        original(self, runner=fake)

    monkeypatch.setattr(lab.KindClusterManager, "__init__", patched)


def _app(tmp_path: Path):
    return create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
        kubeconfig_dir=tmp_path / "kube",
    )


def test_list_empty(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/lab/kind")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_registers_target_and_writes_kubeconfig(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/lab/kind", json={"name": "k8s-lab"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["cluster"]["context"] == "kind-k8s-lab"
    assert body["registered_target"]["address"] == "kind-k8s-lab"
    assert body["registered_target"]["type"] == "kubernetes"
    # kubeconfig written (0600) with the internal server address
    kubeconfig = tmp_path / "kube" / "k8s-lab.kubeconfig"
    assert kubeconfig.exists()
    assert "k8s-lab-control-plane:6443" in kubeconfig.read_text()
    assert kubeconfig.stat().st_mode & 0o777 == 0o600
    # registered through ScopePolicy
    assert ScopePolicy.load(tmp_path / "targets.yaml").resolve("k8s-lab").address == "kind-k8s-lab"


def test_create_without_register(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/lab/kind", json={"name": "k8s-lab", "register_target": False})
    assert resp.status_code == 201
    assert resp.json()["registered_target"] is None
    assert "k8s-lab" not in ScopePolicy.load(tmp_path / "targets.yaml")._targets  # noqa: SLF001


def test_delete_with_purge_removes_target_and_kubeconfig(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/lab/kind", json={"name": "k8s-lab"})
        kubeconfig = tmp_path / "kube" / "k8s-lab.kubeconfig"
        assert kubeconfig.exists()
        resp = client.delete("/api/lab/kind/k8s-lab", params={"purge": True})
    assert resp.status_code == 204
    assert not kubeconfig.exists()
    assert "k8s-lab" not in ScopePolicy.load(tmp_path / "targets.yaml")._targets  # noqa: SLF001


def test_list_reflects_created(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/lab/kind", json={"name": "a", "register_target": False})
        client.post("/api/lab/kind", json={"name": "b", "register_target": False})
        resp = client.get("/api/lab/kind")
    names = {c["name"] for c in resp.json()}
    assert names == {"a", "b"}
