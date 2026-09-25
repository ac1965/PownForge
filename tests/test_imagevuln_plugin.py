from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.imagevuln import ImagevulnPlugin, _cvss_from_grype_vulnerability

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


# CVSS list shape captured from a real `grype alpine:3.10 -o json` run
# (grype 0.99.x, CVE-2022-2068) -- see docs/handbook.md §3.5.
_REAL_GRYPE_CVSS = [
    {"source": "nvd@nist.gov", "type": "Primary", "version": "3.1", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 7.3}},
    {"source": "nvd@nist.gov", "type": "Primary", "version": "2.0", "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "metrics": {"baseScore": 10}},
    {"source": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "type": "Secondary", "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "metrics": {"baseScore": 9.8}},
]


def test_cvss_from_grype_vulnerability_prefers_primary_and_highest_version() -> None:
    result = _cvss_from_grype_vulnerability({"cvss": _REAL_GRYPE_CVSS})
    assert result == (7.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H")


def test_cvss_from_grype_vulnerability_returns_none_when_absent() -> None:
    assert _cvss_from_grype_vulnerability({}) is None
    assert _cvss_from_grype_vulnerability({"cvss": []}) is None


def test_normalize_attaches_cvss_and_native_severity_to_findings(tmp_path: Path) -> None:
    plugin = ImagevulnPlugin()
    execution = _execution(tmp_path)
    execution.path("db-status.json").write_text(DB_STATUS)
    report = json.dumps(
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2022-2068",
                        "severity": "Critical",
                        "fix": {},
                        "cvss": _REAL_GRYPE_CVSS,
                    },
                    "artifact": {"name": "openssl", "version": "3.0.3-r0", "type": "apk"},
                }
            ]
        }
    )
    execution.path("grype.json").write_text(report)

    output = plugin.normalize(_target(), "", "", execution)

    finding = output["_findings"][0]
    assert finding["native_severity"] == "Critical"
    assert finding["cvss_score"] == 7.3
    assert finding["cvss_vector"] == "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"


def test_version_command() -> None:
    assert ImagevulnPlugin().version_command() == ["grype", "version"]


def test_expected_kind_is_host() -> None:
    assert ImagevulnPlugin().expected_kind == TargetKind.HOST
