from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.tls import TlsPlugin

TESTSSL_REPORT = json.dumps(
    [
        {"id": "SSLv2", "ip": "lab-web/1.2.3.4", "port": "443", "severity": "OK", "finding": "not offered"},
        {"id": "TLS1", "ip": "lab-web/1.2.3.4", "port": "443", "severity": "LOW", "finding": "offered (deprecated)"},
        {
            "id": "cert_keyUsage",
            "ip": "lab-web/1.2.3.4",
            "port": "443",
            "severity": "HIGH",
            "finding": "Certificate incorrectly used for key encipherment",
        },
        {"id": "engine_problem", "ip": "/", "port": "443", "severity": "WARN", "finding": "No engine support"},
        {"id": "service", "ip": "lab-web/1.2.3.4", "port": "443", "severity": "INFO", "finding": "HTTP"},
    ]
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target(address: str = "lab-web") -> Target:
    return Target(name="lab-web", kind=TargetKind.HOST, address=address)


def test_build_command_shape_defaults_port_443(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = TlsPlugin()
    monkeypatch.setattr(TlsPlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {}, _execution(tmp_path))

    assert command[0] == "testssl.sh"
    assert command[-1] == "lab-web:443"
    assert "--jsonfile" in command
    assert "-p" in command and "-S" in command and "-f" in command
    assert "--quiet" in command


def test_build_command_honors_port_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = TlsPlugin()
    monkeypatch.setattr(TlsPlugin, "check", lambda self: True)

    command = plugin.build_command(_target(), {"port": "8443"}, _execution(tmp_path))
    assert command[-1] == "lab-web:8443"


def test_build_command_does_not_override_an_explicit_port_in_address(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = TlsPlugin()
    monkeypatch.setattr(TlsPlugin, "check", lambda self: True)

    command = plugin.build_command(_target("lab-web:9443"), {"port": "8443"}, _execution(tmp_path))
    assert command[-1] == "lab-web:9443"  # address already has a port; --option port is ignored


def test_build_command_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = TlsPlugin()
    monkeypatch.setattr(TlsPlugin, "check", lambda self: False)
    with pytest.raises(PluginError):
        plugin.build_command(_target(), {}, _execution(tmp_path))


def test_normalize_maps_severities_and_skips_non_findings(tmp_path: Path) -> None:
    plugin = TlsPlugin()
    execution = _execution(tmp_path)
    execution.path("testssl.json").write_text(TESTSSL_REPORT)

    output = plugin.normalize(_target(), "", "", execution)

    assert len(output["checks"]) == 5
    findings = output["_findings"]
    # OK and INFO are not findings; LOW/HIGH/WARN are.
    assert len(findings) == 3
    by_id = {f["title"].split(":")[0]: f for f in findings}
    assert by_id["TLS1"]["severity"] == "low"
    assert by_id["cert_keyUsage"]["severity"] == "high"
    assert by_id["engine_problem"]["severity"] == "info"  # WARN maps to info


def test_normalize_with_no_report_yields_no_findings(tmp_path: Path) -> None:
    plugin = TlsPlugin()
    output = plugin.normalize(_target(), "", "", _execution(tmp_path))
    assert output["checks"] == []
    assert output["_findings"] == []


def test_parse_version_output_strips_ansi_and_banner_noise() -> None:
    plugin = TlsPlugin()
    raw = (
        "\x1b[1m\n#####################################################################\x1b[m\n"
        "  \x1b[1mtestssl.sh\x1b[m version \x1b[1m3.2.4\x1b[m from \x1b[1mhttps://testssl.sh/\x1b[m\n"
    )
    assert plugin.parse_version_output(raw, "") == "3.2.4"


def test_expected_kind_is_host() -> None:
    assert TlsPlugin().expected_kind == TargetKind.HOST
