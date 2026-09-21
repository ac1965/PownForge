from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

import pytest

from pownforge.core.lab import LabError, LabManager


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
