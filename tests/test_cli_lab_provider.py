from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

import pownforge.cli as cli
from pownforge.core.policy import ScopePolicy

runner = CliRunner()


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


def _patch_compose(monkeypatch, ps_json: str = "[]") -> None:
    # VulhubProvider defaults its runner to subprocess.run; swap that so no
    # real docker is invoked.
    fake = FakeCompose(ps_json)
    import pownforge.core.lab as lab

    original = lab.VulhubProvider.__init__

    def patched(self, root, runner=fake):  # noqa: ANN001
        original(self, root, runner=fake)

    monkeypatch.setattr(lab.VulhubProvider, "__init__", patched)


def test_list_scenarios(tmp_path: Path, monkeypatch) -> None:
    _patch_compose(monkeypatch)
    result = runner.invoke(cli.app, ["lab", "provider", "list", "--vulhub-dir", str(_checkout(tmp_path))])
    assert result.exit_code == 0, result.stdout
    assert "log4j/CVE-2021-44228" in result.stdout


def test_start_with_register_adds_scoped_target(tmp_path: Path, monkeypatch) -> None:
    ps = json.dumps([{"Service": "web", "Publishers": [{"PublishedPort": 8080, "TargetPort": 8080}]}])
    _patch_compose(monkeypatch, ps)
    config = tmp_path / "targets.yaml"
    result = runner.invoke(
        cli.app,
        [
            "lab", "provider", "start", "log4j/CVE-2021-44228",
            "--vulhub-dir", str(_checkout(tmp_path)),
            "--register",
            "--config", str(config),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "127.0.0.1:8080" in result.stdout
    # registered through ScopePolicy, on loopback, named after the scenario
    policy = ScopePolicy.load(config)
    target = policy.resolve("vulhub-log4j-cve-2021-44228")
    assert target.address == "http://127.0.0.1:8080"


def test_cleanup_purge_removes_target(tmp_path: Path, monkeypatch) -> None:
    ps = json.dumps([{"Service": "web", "Publishers": [{"PublishedPort": 8080, "TargetPort": 8080}]}])
    _patch_compose(monkeypatch, ps)
    config = tmp_path / "targets.yaml"
    checkout = _checkout(tmp_path)
    runner.invoke(
        cli.app,
        ["lab", "provider", "start", "log4j/CVE-2021-44228", "--vulhub-dir", str(checkout),
         "--register", "--config", str(config)],
    )
    assert "vulhub-log4j-cve-2021-44228" in ScopePolicy.load(config)._targets  # noqa: SLF001

    result = runner.invoke(
        cli.app,
        ["lab", "provider", "cleanup", "log4j/CVE-2021-44228", "--vulhub-dir", str(checkout),
         "--purge", "--config", str(config)],
    )
    assert result.exit_code == 0, result.stdout
    assert "vulhub-log4j-cve-2021-44228" not in ScopePolicy.load(config)._targets  # noqa: SLF001


def test_list_missing_dir_errors(tmp_path: Path, monkeypatch) -> None:
    _patch_compose(monkeypatch)
    result = runner.invoke(cli.app, ["lab", "provider", "list", "--vulhub-dir", str(tmp_path / "nope")])
    assert result.exit_code == 1
    assert "does not exist" in result.stderr
