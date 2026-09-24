from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.httpprobe import HttpProbePlugin

HTTPX_JSONL = "\n".join(
    [
        json.dumps(
            {
                "url": "https://a.example",
                "status_code": 200,
                "title": "A",
                "webserver": "nginx",
                "tech": ["Nginx"],
            }
        ),
        json.dumps(
            {
                "url": "https://b.example",
                "status_code": 302,
                "location": "https://b.example/login",
            }
        ),
    ]
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _anchor() -> Target:
    return Target(name="anchor", kind=TargetKind.HOST, address="example.com")


def test_build_command_shape_with_already_resolved_hosts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """By the time build_command() runs, ScanRunner has already replaced
    `hosts` with comma-separated addresses (see test_host_list_option.py) --
    this test exercises build_command() with that already-resolved shape."""
    plugin = HttpProbePlugin()
    monkeypatch.setattr(HttpProbePlugin, "check", lambda self: True)
    execution = _execution(tmp_path)

    command = plugin.build_command(_anchor(), {"hosts": "https://a.example,https://b.example"}, execution)

    assert command[0] == "httpx"
    hosts_path = execution.path("hosts.txt")
    assert hosts_path.read_text() == "https://a.example\nhttps://b.example\n"
    assert "-l" in command and str(hosts_path) in command
    assert "-rate-limit" in command
    assert command[command.index("-rate-limit") + 1] == "10"  # conservative default
    assert "-follow-redirects" not in command and "-fr" not in command


def test_build_command_honors_rate_limit_and_timeout_options(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = HttpProbePlugin()
    monkeypatch.setattr(HttpProbePlugin, "check", lambda self: True)

    command = plugin.build_command(
        _anchor(), {"hosts": "https://a.example", "rate_limit": "5", "timeout": "20"}, _execution(tmp_path)
    )
    assert command[command.index("-rate-limit") + 1] == "5"
    assert command[command.index("-timeout") + 1] == "20"


def test_build_command_rejects_when_no_authorized_hosts_remain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty `hosts` value here means every requested name was rejected
    by ScopePolicy upstream (or none were given) -- must fail loudly, not
    silently run httpx against nothing."""
    plugin = HttpProbePlugin()
    monkeypatch.setattr(HttpProbePlugin, "check", lambda self: True)
    with pytest.raises(PluginError, match="no authorized hosts"):
        plugin.build_command(_anchor(), {"hosts": ""}, _execution(tmp_path))


def test_build_command_rejects_non_integer_rate_limit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = HttpProbePlugin()
    monkeypatch.setattr(HttpProbePlugin, "check", lambda self: True)
    with pytest.raises(PluginError, match="rate_limit"):
        plugin.build_command(_anchor(), {"hosts": "https://a.example", "rate_limit": "fast"}, _execution(tmp_path))


def test_build_command_rejects_non_host_kind_anchor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = HttpProbePlugin()
    monkeypatch.setattr(HttpProbePlugin, "check", lambda self: True)
    target = Target(name="u", kind=TargetKind.URL, address="https://x.example")
    with pytest.raises(PluginError, match="requires a"):
        plugin.build_command(target, {"hosts": "https://a.example"}, _execution(tmp_path))


def test_normalize_parses_jsonl_results_and_surfaces_excluded_hosts(tmp_path: Path) -> None:
    plugin = HttpProbePlugin()
    execution = _execution(tmp_path)
    execution.data["excluded_hosts"] = [{"name": "sub-c", "reason": "not authorized"}]

    output = plugin.normalize(_anchor(), HTTPX_JSONL, "", execution)

    assert output["probed"] == 2
    assert output["results"][0]["title"] == "A"
    assert output["results"][0]["tech"] == ["Nginx"]
    assert output["results"][1]["status_code"] == 302
    assert output["results"][1]["location"] == "https://b.example/login"
    assert output["excluded_hosts"] == [{"name": "sub-c", "reason": "not authorized"}]
    # Pure triage: no findings (matches the `httpx` plugin's own convention).
    assert "_findings" not in output


def test_normalize_with_no_output_and_no_exclusions(tmp_path: Path) -> None:
    plugin = HttpProbePlugin()
    output = plugin.normalize(_anchor(), "", "", _execution(tmp_path))
    assert output["probed"] == 0
    assert output["excluded_hosts"] == []


def test_version_command() -> None:
    assert HttpProbePlugin().version_command() == ["httpx", "-version"]


def test_expected_kind_is_host() -> None:
    assert HttpProbePlugin().expected_kind == TargetKind.HOST


def test_host_list_option_is_declared() -> None:
    assert HttpProbePlugin().host_list_option == "hosts"


def test_hosts_option_is_required() -> None:
    schema = {opt.name: opt for opt in HttpProbePlugin().options_schema}
    assert schema["hosts"].required is True
