from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from pownforge.core.lab import LabError, VulhubProvider


@dataclass
class FakeResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class FakeCompose:
    """Records `docker compose` invocations and returns canned `ps` output."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.ps_json = "[]"
        self.fail_on: set[str] = set()

    def __call__(self, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        # command looks like ["docker", "compose", "-f", <file>, <verb>, ...]
        verb = command[4] if len(command) > 4 else ""
        if verb in self.fail_on:
            return FakeResult(returncode=1, stderr=f"{verb} failed")  # type: ignore[return-value]
        if verb == "ps":
            return FakeResult(returncode=0, stdout=self.ps_json)  # type: ignore[return-value]
        return FakeResult(returncode=0)  # type: ignore[return-value]

    def compose_verbs(self) -> list[str]:
        return [c[4] for c in self.calls if len(c) > 4]


def _vulhub_checkout(tmp_path: Path) -> Path:
    root = tmp_path / "vulhub"
    (root / "log4j" / "CVE-2021-44228").mkdir(parents=True)
    (root / "log4j" / "CVE-2021-44228" / "docker-compose.yml").write_text("services: {}\n")
    (root / "spring" / "CVE-2022-22965").mkdir(parents=True)
    (root / "spring" / "CVE-2022-22965" / "compose.yaml").write_text("services: {}\n")
    (root / "notes.txt").write_text("not a scenario")
    return root


def test_list_scenarios_finds_compose_dirs(tmp_path: Path) -> None:
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=FakeCompose())
    ids = [s.id for s in provider.list_scenarios()]
    assert ids == ["log4j/CVE-2021-44228", "spring/CVE-2022-22965"]


def test_list_scenarios_missing_root_raises(tmp_path: Path) -> None:
    provider = VulhubProvider(tmp_path / "nope", runner=FakeCompose())
    with pytest.raises(LabError, match="does not exist"):
        provider.list_scenarios()


def test_start_runs_compose_up_and_parses_ports(tmp_path: Path) -> None:
    compose = FakeCompose()
    compose.ps_json = json.dumps(
        [{"Service": "web", "Publishers": [{"PublishedPort": 8080, "TargetPort": 8080}]}]
    )
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=compose)
    scenario = provider.start("log4j/CVE-2021-44228")
    assert compose.compose_verbs()[0] == "up"
    assert scenario.running is True
    assert scenario.published_ports[0].host_port == 8080
    assert scenario.published_ports[0].service == "web"


def test_start_failure_raises(tmp_path: Path) -> None:
    compose = FakeCompose()
    compose.fail_on.add("up")
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=compose)
    with pytest.raises(LabError, match="failed to start"):
        provider.start("log4j/CVE-2021-44228")


def test_status_reports_stopped_when_no_containers(tmp_path: Path) -> None:
    compose = FakeCompose()
    compose.ps_json = "[]"
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=compose)
    state = provider.status("log4j/CVE-2021-44228")
    assert state.running is False
    assert state.published_ports == []


def test_status_parses_jsonl_output(tmp_path: Path) -> None:
    compose = FakeCompose()
    compose.ps_json = "\n".join(
        json.dumps(row)
        for row in [{"Service": "web", "Publishers": [{"PublishedPort": 9000, "TargetPort": 80}]}]
    )
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=compose)
    state = provider.status("log4j/CVE-2021-44228")
    assert state.running is True
    assert state.published_ports[0].host_port == 9000
    assert state.published_ports[0].container_port == 80


def test_reset_runs_down_then_up(tmp_path: Path) -> None:
    compose = FakeCompose()
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=compose)
    provider.reset("log4j/CVE-2021-44228")
    verbs = compose.compose_verbs()
    assert verbs[0] == "down"
    assert "up" in verbs


def test_cleanup_removes_volumes(tmp_path: Path) -> None:
    compose = FakeCompose()
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=compose)
    provider.cleanup("log4j/CVE-2021-44228")
    down = next(c for c in compose.calls if c[4] == "down")
    assert "-v" in down and "--remove-orphans" in down


def test_scenario_outside_root_is_rejected(tmp_path: Path) -> None:
    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=FakeCompose())
    with pytest.raises(LabError, match="outside the Vulhub root"):
        provider.start("../../etc")


def test_unknown_scenario_without_compose_file_raises(tmp_path: Path) -> None:
    root = _vulhub_checkout(tmp_path)
    (root / "empty").mkdir()
    provider = VulhubProvider(root, runner=FakeCompose())
    with pytest.raises(LabError, match="no docker-compose file"):
        provider.start("empty")


def test_missing_docker_raises_clear_error(tmp_path: Path) -> None:
    def missing(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    provider = VulhubProvider(_vulhub_checkout(tmp_path), runner=missing)
    with pytest.raises(LabError, match="docker"):
        provider.start("log4j/CVE-2021-44228")
