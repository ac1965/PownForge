"""refactor §18 step 1 (extended to scan): application/scans.py is the
single place a ScanRunner gets built and run for the CLI's synchronous
`scan <plugin>` commands, replacing cli.py::_run_scan's own five
composition-root calls plus ScanRunner() construction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pownforge.application.scans import run_scan
from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry, RegistryError
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginExecution


class _EchoPlugin(Plugin):
    name = "echo"
    version = "0.0.1"
    description = "test double that just echoes the target address"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution) -> dict[str, Any]:
        return {"raw_stdout": raw_stdout, "raw_stderr": raw_stderr}


def _init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    config = tmp_path / "targets.yaml"
    ScopePolicy(targets={}).save(config)
    policy = ScopePolicy.load(config)
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    policy.save(config)
    workdir = tmp_path / "state"

    registry = PluginRegistry()
    registry.register(_EchoPlugin())
    monkeypatch.setattr("pownforge.application.scans.build_registry", lambda: registry)
    return config, workdir


def test_run_scan_executes_and_persists(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, workdir = _init(tmp_path, monkeypatch)

    record = run_scan(config, workdir, "echo", "lab", {})

    assert record.evidence.returncode == 0
    assert "127.0.0.1" in record.output["raw_stdout"]
    assert EvidenceStore(workdir / "runs").load(record.run_id).run_id == record.run_id


def test_run_scan_raises_policy_error_for_unregistered_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, workdir = _init(tmp_path, monkeypatch)

    with pytest.raises(PolicyError):
        run_scan(config, workdir, "echo", "nope", {})


def test_run_scan_forwards_on_line_callback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, workdir = _init(tmp_path, monkeypatch)
    lines: list[str] = []

    run_scan(config, workdir, "echo", "lab", {}, on_line=lines.append)

    assert lines == ["127.0.0.1"]


def test_run_scan_raises_registry_error_for_unregistered_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, workdir = _init(tmp_path, monkeypatch)

    with pytest.raises(RegistryError):
        run_scan(config, workdir, "no-such-plugin", "lab", {})
