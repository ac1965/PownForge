from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.imagevuln import ImagevulnPlugin

DB_STATUS = json.dumps({"built": "2026-09-24T06:31:52Z", "valid": True})

GRYPE_REPORT = json.dumps(
    {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-36159",
                    "severity": "Critical",
                    "fix": {"versions": ["2.10.7-r0"], "state": "fixed"},
                },
                "artifact": {"name": "apk-tools", "version": "2.10.6-r0", "type": "apk"},
            },
            # Duplicate (id, package, version) must be deduped.
            {
                "vulnerability": {
                    "id": "CVE-2021-36159",
                    "severity": "Critical",
                    "fix": {"versions": ["2.10.7-r0"], "state": "fixed"},
                },
                "artifact": {"name": "apk-tools", "version": "2.10.6-r0", "type": "apk"},
            },
            {
                "vulnerability": {"id": "CVE-9999-0000", "severity": "SomethingNew", "fix": {}},
                "artifact": {"name": "made-up-pkg", "version": "1.0.0", "type": "apk"},
            },
        ],
    }
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target() -> Target:
    return Target(name="alpine-image", kind=TargetKind.HOST, address="alpine:3.10")


def test_build_command_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = ImagevulnPlugin()
    monkeypatch.setattr(ImagevulnPlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {}, _execution(tmp_path))

    assert command[0] == "sh" and command[1] == "-c"
    script = command[2]
    assert "GRYPE_DB_AUTO_UPDATE=false" in script
    assert "GRYPE_CHECK_FOR_APP_UPDATE=false" in script
    assert "grype db status -o json" in script
    assert "grype alpine:3.10 -o json" in script
    assert "--only-fixed" not in script  # default is false


def test_build_command_honors_only_fixed_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = ImagevulnPlugin()
    monkeypatch.setattr(ImagevulnPlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {"only-fixed": "true"}, _execution(tmp_path))
    assert "--only-fixed" in command[2]


def test_build_command_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = ImagevulnPlugin()
    monkeypatch.setattr(ImagevulnPlugin, "check", lambda self: False)
    with pytest.raises(PluginError):
        plugin.build_command(_target(), {}, _execution(tmp_path))


def test_normalize_parses_report_dedupes_maps_severity_and_records_db_build_time(tmp_path: Path) -> None:
    plugin = ImagevulnPlugin()
    execution = _execution(tmp_path)
    execution.path("db-status.json").write_text(DB_STATUS)
    execution.path("grype.json").write_text(GRYPE_REPORT)

    output = plugin.normalize(_target(), "", "", execution)

    assert output["db_built_at"] == "2026-09-24T06:31:52Z"
    assert len(output["matches"]) == 2  # deduped the repeated CVE-2021-36159 hit

    findings = output["_findings"]
    assert len(findings) == 2
    by_title_prefix = {f["title"].split(" in ")[0]: f for f in findings}
    critical = by_title_prefix["CVE-2021-36159"]
    assert critical["severity"] == "critical"
    assert "apk-tools@2.10.6-r0" in critical["title"]
    assert "fixed in 2.10.7-r0" in critical["detail"]

    unmapped = by_title_prefix["CVE-9999-0000"]
    assert unmapped["severity"] == "info"  # unmapped grype severity falls back, not dropped
    assert "no fix available" in unmapped["detail"]


def test_normalize_with_no_files_yields_no_matches(tmp_path: Path) -> None:
    plugin = ImagevulnPlugin()
    output = plugin.normalize(_target(), "", "", _execution(tmp_path))
    assert output["matches"] == []
    assert output["_findings"] == []
    assert output["db_built_at"] is None


def test_version_command() -> None:
    assert ImagevulnPlugin().version_command() == ["grype", "version"]


def test_expected_kind_is_host() -> None:
    assert ImagevulnPlugin().expected_kind == TargetKind.HOST
