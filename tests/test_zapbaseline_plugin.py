from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.zapbaseline import ZapBaselinePlugin

ZAP_REPORT = json.dumps(
    {
        "site": [
            {
                "@name": "http://lab-web:3000",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "name": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "3",
                        "instances": [
                            {"uri": "http://lab-web:3000"},
                            {"uri": "http://lab-web:3000/sitemap.xml"},
                        ],
                    },
                    {
                        "pluginid": "10096",
                        "name": "Timestamp Disclosure - Unix",
                        "riskcode": "1",
                        "instances": [{"uri": "http://lab-web:3000/styles.css"}],
                    },
                    {
                        "pluginid": "99999",
                        "name": "Made-up unmapped riskcode",
                        "riskcode": "7",
                        "instances": [],
                    },
                ],
            }
        ],
    }
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target() -> Target:
    return Target(name="lab-web", kind=TargetKind.URL, address="http://lab-web:3000")


def test_build_command_shape_defaults_to_pownforge_lab_network(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = ZapBaselinePlugin()
    monkeypatch.setattr(ZapBaselinePlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {}, _execution(tmp_path))

    assert command[0] == "docker" and command[1] == "run"
    assert "--network" in command and "pownforge-lab" in command
    assert "zap-baseline.py" in command
    assert "-t" in command and "http://lab-web:3000" in command
    assert "-I" in command
    # Never zap-full-scan.py / zap-api-scan.py, and no such flag exists to
    # pass in the first place -- zap-baseline.py is passive-only by design.
    assert not any("full-scan" in part or "api-scan" in part for part in command)


def test_build_command_empty_network_option_uses_default_bridge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = ZapBaselinePlugin()
    monkeypatch.setattr(ZapBaselinePlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {"network": ""}, _execution(tmp_path))
    assert "--network" not in command


def test_build_command_honors_spider_minutes_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = ZapBaselinePlugin()
    monkeypatch.setattr(ZapBaselinePlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {"spider_minutes": "3"}, _execution(tmp_path))
    assert command[command.index("-m") + 1] == "3"


def test_build_command_rejects_non_integer_spider_minutes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = ZapBaselinePlugin()
    monkeypatch.setattr(ZapBaselinePlugin, "check", lambda self: True)
    with pytest.raises(PluginError, match="spider_minutes"):
        plugin.build_command(_target(), {"spider_minutes": "forever"}, _execution(tmp_path))


def test_build_command_makes_the_scratch_dir_writable_for_the_zap_container(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ZAP's official image runs as its own baked-in user, not whatever uid
    ran pownforge -- the mounted scratch dir must be writable by both."""
    plugin = ZapBaselinePlugin()
    monkeypatch.setattr(ZapBaselinePlugin, "check", lambda self: True)
    execution = _execution(tmp_path)
    execution.workdir.chmod(0o700)

    plugin.build_command(_target(), {}, execution)

    mode = stat.S_IMODE(execution.workdir.stat().st_mode)
    assert mode == 0o777


def test_build_command_rejects_non_url_kind(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = ZapBaselinePlugin()
    monkeypatch.setattr(ZapBaselinePlugin, "check", lambda self: True)
    target = Target(name="h", kind=TargetKind.HOST, address="lab-web")
    with pytest.raises(PluginError, match="requires a"):
        plugin.build_command(target, {}, _execution(tmp_path))


def test_normalize_parses_alerts_maps_riskcode_and_counts_instances(tmp_path: Path) -> None:
    plugin = ZapBaselinePlugin()
    execution = _execution(tmp_path)
    execution.path("report.json").write_text(ZAP_REPORT)

    output = plugin.normalize(_target(), "", "", execution)

    assert len(output["alerts"]) == 3
    findings = output["_findings"]
    assert len(findings) == 3
    by_title = {f["title"]: f for f in findings}
    csp = by_title["Content Security Policy (CSP) Header Not Set"]
    assert csp["severity"] == "medium"
    assert "2 instance(s)" in csp["detail"]

    ts = by_title["Timestamp Disclosure - Unix"]
    assert ts["severity"] == "low"

    unmapped = by_title["Made-up unmapped riskcode"]
    assert unmapped["severity"] == "info"  # unrecognized riskcode falls back, not dropped


def test_normalize_with_no_report_yields_no_alerts(tmp_path: Path) -> None:
    plugin = ZapBaselinePlugin()
    output = plugin.normalize(_target(), "", "", _execution(tmp_path))
    assert output["alerts"] == []
    assert output["_findings"] == []


def test_version_command() -> None:
    assert ZapBaselinePlugin().version_command() == ["docker", "--version"]


def test_expected_kind_is_url() -> None:
    assert ZapBaselinePlugin().expected_kind == TargetKind.URL


def test_required_tool_is_docker_not_zap() -> None:
    assert ZapBaselinePlugin().required_tool == "docker"
