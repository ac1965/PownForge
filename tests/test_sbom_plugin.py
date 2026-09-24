from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.sbom import SbomPlugin

CYCLONEDX_SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "alpine-baselayout", "version": "3.1.2-r0", "type": "library", "purl": "pkg:apk/alpine-baselayout@3.1.2-r0"},
            {"name": "busybox", "version": "1.30.1-r5", "type": "library", "purl": "pkg:apk/busybox@1.30.1-r5"},
            {"name": "some-app", "version": "2.0.0", "type": "application", "purl": "pkg:generic/some-app@2.0.0"},
        ],
    }
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target() -> Target:
    return Target(name="alpine-image", kind=TargetKind.HOST, address="alpine:3.10")


def test_build_command_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SbomPlugin()
    monkeypatch.setattr(SbomPlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {}, _execution(tmp_path))

    assert command[0] == "syft"
    assert command[1] == "scan"
    assert command[2] == "alpine:3.10"
    assert "--scope" in command and "squashed" in command
    assert "--quiet" in command
    assert not any("enrich" in part for part in command)  # no online enrichment


def test_build_command_honors_scope_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SbomPlugin()
    monkeypatch.setattr(SbomPlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {"scope": "all-layers"}, _execution(tmp_path))
    assert command[command.index("--scope") + 1] == "all-layers"


def test_build_command_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SbomPlugin()
    monkeypatch.setattr(SbomPlugin, "check", lambda self: False)
    with pytest.raises(PluginError):
        plugin.build_command(_target(), {}, _execution(tmp_path))


def test_normalize_parses_sbom_and_summarizes_by_type(tmp_path: Path) -> None:
    plugin = SbomPlugin()
    execution = _execution(tmp_path)
    execution.path("sbom.cdx.json").write_text(CYCLONEDX_SBOM)

    output = plugin.normalize(_target(), "", "", execution)

    assert output["package_count"] == 3
    assert output["packages_by_type"] == {"library": 2, "application": 1}
    assert len(output["components"]) == 3
    assert output["components"][0]["name"] == "alpine-baselayout"
    # An SBOM is inventory, not a vulnerability -- never turned into findings.
    assert "_findings" not in output


def test_normalize_with_no_report_file_yields_empty_sbom(tmp_path: Path) -> None:
    plugin = SbomPlugin()
    output = plugin.normalize(_target(), "", "", _execution(tmp_path))
    assert output["package_count"] == 0
    assert output["components"] == []


def test_version_command() -> None:
    assert SbomPlugin().version_command() == ["syft", "version"]


def test_expected_kind_is_host() -> None:
    assert SbomPlugin().expected_kind == TargetKind.HOST
