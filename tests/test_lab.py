from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

import pytest

from pownforge.core.lab import KindClusterManager, LabError, LabManager


@dataclass
class FakeResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class FakeDocker:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.network_exists = False
        self.ps_output = ""
        self.fail_on: set[str] = set()

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        if command[:2] == ["docker", "network"] and command[2] == "inspect":
            return FakeResult(returncode=0 if self.network_exists else 1)  # type: ignore[return-value]
        if command[:3] == ["docker", "network", "create"]:
            self.network_exists = True
            return FakeResult(returncode=0)  # type: ignore[return-value]
        if command[:2] == ["docker", "run"]:
            if "run" in self.fail_on:
                return FakeResult(returncode=1, stderr="boom")  # type: ignore[return-value]
            return FakeResult(returncode=0, stdout="containerid\n")  # type: ignore[return-value]
        if command[:2] == ["docker", "rm"]:
            if "rm" in self.fail_on:
                return FakeResult(returncode=1, stderr="no such container")  # type: ignore[return-value]
            return FakeResult(returncode=0)  # type: ignore[return-value]
        if command[:2] == ["docker", "ps"]:
            return FakeResult(returncode=0, stdout=self.ps_output)  # type: ignore[return-value]
        raise AssertionError(f"unexpected docker command: {command}")


def test_add_creates_network_when_missing() -> None:
    docker = FakeDocker()
    manager = LabManager(network="test-lab", runner=docker)
    host = manager.add("target1", "vulnerable/image")
    assert host.name == "target1"
    assert docker.network_exists is True
    assert any(c[:3] == ["docker", "network", "create"] for c in docker.calls)
    assert any(c[:3] == ["docker", "network", "create"] and "--internal" in c for c in docker.calls)


def test_add_skips_network_create_when_present() -> None:
    docker = FakeDocker()
    docker.network_exists = True
    manager = LabManager(network="test-lab", runner=docker)
    manager.add("target1", "vulnerable/image")
    assert not any(c[:3] == ["docker", "network", "create"] for c in docker.calls)


def test_add_keeps_stdin_open_so_services_and_bash_style_images_stay_running() -> None:
    docker = FakeDocker()
    docker.network_exists = True
    manager = LabManager(network="test-lab", runner=docker)
    manager.add("target1", "vulnerable/image")
    run_call = next(c for c in docker.calls if c[:2] == ["docker", "run"])
    assert "-i" in run_call


def test_add_raises_on_docker_failure() -> None:
    docker = FakeDocker()
    docker.network_exists = True
    docker.fail_on.add("run")
    manager = LabManager(network="test-lab", runner=docker)
    with pytest.raises(LabError):
        manager.add("target1", "vulnerable/image")


def test_remove_raises_on_failure() -> None:
    docker = FakeDocker()
    docker.fail_on.add("rm")
    manager = LabManager(network="test-lab", runner=docker)
    with pytest.raises(LabError):
        manager.remove("target1")


def test_add_raises_clear_error_when_docker_missing() -> None:
    def missing_docker(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    manager = LabManager(network="test-lab", runner=missing_docker)
    with pytest.raises(LabError, match="docker"):
        manager.add("target1", "vulnerable/image")


def test_list_parses_docker_ps_json_lines() -> None:
    docker = FakeDocker()
    docker.ps_output = "\n".join(
        json.dumps(row)
        for row in [
            {"Names": "target1", "Image": "vulnerable/image", "Status": "Up 2 minutes"},
            {"Names": "target2", "Image": "other/image", "Status": "Exited (0)"},
        ]
    )
    manager = LabManager(network="test-lab", runner=docker)
    hosts = manager.list()
    assert [h.name for h in hosts] == ["target1", "target2"]
    assert hosts[0].image == "vulnerable/image"


class FakeKind:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.clusters: list[str] = []
        self.fail_on: set[str] = set()

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        if command[:3] == ["kind", "create", "cluster"]:
            if "create" in self.fail_on:
                return FakeResult(returncode=1, stderr="node(s) already exist")  # type: ignore[return-value]
            self.clusters.append(command[command.index("--name") + 1])
            return FakeResult()  # type: ignore[return-value]
        if command[:3] == ["kind", "get", "kubeconfig"]:
            name = command[command.index("--name") + 1]
            return FakeResult(stdout=f"server: https://{name}-control-plane:6443\n")  # type: ignore[return-value]
        if command[:3] == ["kind", "delete", "cluster"]:
            if "delete" in self.fail_on:
                return FakeResult(returncode=1, stderr="boom")  # type: ignore[return-value]
            return FakeResult()  # type: ignore[return-value]
        if command[:3] == ["kind", "get", "clusters"]:
            return FakeResult(stdout="".join(f"{c}\n" for c in self.clusters))  # type: ignore[return-value]
        raise AssertionError(f"unexpected kind command: {command}")


def test_kind_create_exports_internal_kubeconfig(tmp_path) -> None:
    kind = FakeKind()
    path = tmp_path / "config" / "lab1.kubeconfig"
    cluster = KindClusterManager(runner=kind).create("lab1", path)
    assert cluster.context == "kind-lab1"
    assert ["kind", "get", "kubeconfig", "--internal", "--name", "lab1"] in kind.calls
    assert "lab1-control-plane:6443" in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600


def test_kind_create_passes_cluster_config(tmp_path) -> None:
    kind = FakeKind()
    KindClusterManager(runner=kind).create("lab1", tmp_path / "k", tmp_path / "kind.yaml")
    assert kind.calls[0] == [
        "kind", "create", "cluster", "--name", "lab1", "--config", str(tmp_path / "kind.yaml")
    ]


def test_kind_create_failure_writes_no_kubeconfig(tmp_path) -> None:
    kind = FakeKind()
    kind.fail_on.add("create")
    path = tmp_path / "lab1.kubeconfig"
    with pytest.raises(LabError, match="already exist"):
        KindClusterManager(runner=kind).create("lab1", path)
    assert not path.exists()


def test_kind_delete_raises_on_failure() -> None:
    kind = FakeKind()
    kind.fail_on.add("delete")
    with pytest.raises(LabError):
        KindClusterManager(runner=kind).delete("lab1")


def test_kind_list_parses_cluster_names() -> None:
    kind = FakeKind()
    kind.clusters = ["a", "b"]
    clusters = KindClusterManager(runner=kind).list()
    assert [(c.name, c.context) for c in clusters] == [("a", "kind-a"), ("b", "kind-b")]


def test_kind_missing_binary_raises_clear_error(tmp_path) -> None:
    def missing(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    with pytest.raises(LabError, match="kind"):
        KindClusterManager(runner=missing).list()
