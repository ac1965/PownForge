from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from pownforge.core.lab import LabError, VulhubProvider

# `start()` runs `up` against a rewritten temp compose file with
# `--project-directory <scenario dir>` inserted before the verb (see
# VulhubProvider._localhost_only_up_command) -- every other verb still
# runs as `["docker", "compose", "-f", <file>, <verb>, ...]`. Recognizing
# the verb by membership rather than a fixed index keeps these fakes
# correct across both shapes.
_KNOWN_VERBS = {"up", "down", "ps", "stop"}


def _verb(command: list[str]) -> str:
    return next((tok for tok in command if tok in _KNOWN_VERBS), "")


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
        verb = _verb(command)
        if verb in self.fail_on:
            return FakeResult(returncode=1, stderr=f"{verb} failed")  # type: ignore[return-value]
        if verb == "ps":
            return FakeResult(returncode=0, stdout=self.ps_json)  # type: ignore[return-value]
        return FakeResult(returncode=0)  # type: ignore[return-value]

    def compose_verbs(self) -> list[str]:
        return [_verb(c) for c in self.calls]


def _vulhub_checkout(tmp_path: Path) -> Path:
    root = tmp_path / "vulhub"
    (root / "log4j" / "CVE-2021-44228").mkdir(parents=True)
    (root / "log4j" / "CVE-2021-44228" / "docker-compose.yml").write_text("services: {}\n")
    (root / "spring" / "CVE-2022-22965").mkdir(parents=True)
    (root / "spring" / "CVE-2022-22965" / "compose.yaml").write_text("services: {}\n")
    (root / "notes.txt").write_text("not a scenario")
    return root


def _vulhub_checkout_with_ports(tmp_path: Path) -> Path:
    """A scenario whose compose file publishes ports the way real Vulhub
    scenarios do (see log4j/CVE-2021-44228 upstream): plain "HOST:CONTAINER"
    strings with no host IP, which Docker would otherwise bind on every
    interface."""
    root = tmp_path / "vulhub"
    scenario = root / "log4j" / "CVE-2021-44228"
    scenario.mkdir(parents=True)
    (scenario / "docker-compose.yml").write_text(
        "version: '2'\n"
        "services:\n"
        "  solr:\n"
        "    image: vulhub/solr:8.11.0\n"
        "    ports:\n"
        "      - \"8983:8983\"\n"
        "      - \"5005:5005\"\n"
        "    volumes:\n"
        "      - ./poc.jsp:/webapp/poc.jsp\n"
    )
    (scenario / "poc.jsp").write_text("<!-- fixture -->\n")
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


def test_start_forces_published_ports_to_localhost(tmp_path: Path) -> None:
    """docs/handbook.md §7's "isolated lab host" precondition assumes the
    scenario is only reachable from that host -- Vulhub's own compose
    files publish with no host IP, which Docker binds on every interface
    (confirmed empirically on Docker Desktop for Mac). `start()` must
    never run `up` against Vulhub's own file unmodified."""
    root = _vulhub_checkout_with_ports(tmp_path)
    scenario_dir = root / "log4j" / "CVE-2021-44228"
    original = (scenario_dir / "docker-compose.yml").read_text()
    seen: dict[str, Any] = {}

    def fake_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        verb = _verb(command)
        if verb == "up":
            f_index = command.index("-f")
            tmp_file = Path(command[f_index + 1])
            seen["command"] = command
            seen["tmp_path"] = tmp_file
            seen["tmp_contents_at_call_time"] = tmp_file.read_text()
        return FakeResult(returncode=0, stdout="[]" if verb == "ps" else "")  # type: ignore[return-value]

    provider = VulhubProvider(root, runner=fake_runner)
    provider.start("log4j/CVE-2021-44228")

    # Vulhub's own file on disk is untouched.
    assert (scenario_dir / "docker-compose.yml").read_text() == original

    rewritten = yaml.safe_load(seen["tmp_contents_at_call_time"])
    assert rewritten["services"]["solr"]["ports"] == ["127.0.0.1:8983:8983", "127.0.0.1:5005:5005"]
    # Relative paths (the poc.jsp volume mount) must still resolve against
    # the real scenario directory, not wherever the temp file landed.
    assert "--project-directory" in seen["command"]
    pd_index = seen["command"].index("--project-directory")
    assert Path(seen["command"][pd_index + 1]) == scenario_dir
    # The temp compose file is cleaned up once `up` has run.
    assert not seen["tmp_path"].exists()


def test_start_forces_already_wildcard_port_to_localhost(tmp_path: Path) -> None:
    """A scenario that already spells out "0.0.0.0:PORT:PORT" (unlike
    plain Vulhub scenarios, which never specify a host IP) must still be
    forced to 127.0.0.1, not left as an explicit wildcard bind."""
    root = tmp_path / "vulhub"
    scenario = root / "custom" / "wide-open"
    scenario.mkdir(parents=True)
    (scenario / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports:\n      - \"0.0.0.0:8080:80\"\n"
    )
    seen: dict[str, Any] = {}

    def fake_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if _verb(command) == "up":
            tmp_file = Path(command[command.index("-f") + 1])
            seen["ports"] = yaml.safe_load(tmp_file.read_text())["services"]["web"]["ports"]
        return FakeResult(returncode=0)  # type: ignore[return-value]

    VulhubProvider(root, runner=fake_runner).start("custom/wide-open")
    assert seen["ports"] == ["127.0.0.1:8080:80"]


def test_status_reorders_published_ports_to_match_compose_declaration(tmp_path: Path) -> None:
    """Real-machine regression (found running the log4j/CVE-2021-44228
    smoke test, 2026-09-25): the scenario's compose file declares 8983
    (Solr admin, the port its own PoC targets) before 5005 (a JDWP debug
    port), but `docker compose ps --format json` reported 5005 first --
    `lab_provider start --register` (cli/lab_provider.py) blindly
    registers `published_ports[0]`, so it silently registered the wrong
    port. `status()` must reorder `docker compose ps`'s output back into
    the file's own declared order."""
    compose = FakeCompose()
    # Deliberately reversed vs. the compose file's declaration order
    # (8983 then 5005) to reproduce the real `docker compose ps` behavior.
    compose.ps_json = json.dumps(
        [
            {
                "Service": "solr",
                "Publishers": [
                    {"PublishedPort": 5005, "TargetPort": 5005},
                    {"PublishedPort": 8983, "TargetPort": 8983},
                ],
            }
        ]
    )
    provider = VulhubProvider(_vulhub_checkout_with_ports(tmp_path), runner=compose)

    state = provider.status("log4j/CVE-2021-44228")

    assert [p.host_port for p in state.published_ports] == [8983, 5005]


def test_start_with_register_picks_the_compose_declared_first_port(tmp_path: Path) -> None:
    """End-to-end version of the regression above, through `start()` --
    the port `--register` would actually pick."""
    compose = FakeCompose()
    compose.ps_json = json.dumps(
        [
            {
                "Service": "solr",
                "Publishers": [
                    {"PublishedPort": 5005, "TargetPort": 5005},
                    {"PublishedPort": 8983, "TargetPort": 8983},
                ],
            }
        ]
    )
    provider = VulhubProvider(_vulhub_checkout_with_ports(tmp_path), runner=compose)

    scenario = provider.start("log4j/CVE-2021-44228")

    assert scenario.published_ports[0].host_port == 8983


def test_reorder_leaves_unmatched_ports_in_original_relative_order(tmp_path: Path) -> None:
    """A port `docker compose ps` reports that isn't found in the compose
    file's own declared order (e.g. an env-var-interpolated port Compose
    resolved at runtime) must not be dropped -- it's appended after every
    matched port, keeping its position relative to other unmatched ports."""
    root = tmp_path / "vulhub"
    scenario = root / "custom" / "mixed"
    scenario.mkdir(parents=True)
    (scenario / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    ports:\n      - \"8080:80\"\n"
    )
    compose = FakeCompose()
    compose.ps_json = json.dumps(
        [
            {
                "Service": "web",
                "Publishers": [
                    {"PublishedPort": 9999, "TargetPort": 9999},  # not in the file (unmatched)
                    {"PublishedPort": 8080, "TargetPort": 80},  # matches the declared port
                ],
            }
        ]
    )
    provider = VulhubProvider(root, runner=compose)

    state = provider.status("custom/mixed")

    assert [p.host_port for p in state.published_ports] == [8080, 9999]


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
