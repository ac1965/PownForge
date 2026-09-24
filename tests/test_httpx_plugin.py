from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.httpx_probe import HttpxProbePlugin


@pytest.fixture
def plugin(monkeypatch: pytest.MonkeyPatch) -> HttpxProbePlugin:
    monkeypatch.setattr("pownforge.plugins.httpx_probe.shutil.which", lambda _: "/usr/bin/httpx")
    return HttpxProbePlugin()


@pytest.fixture
def execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target(address: str = "http://lab-web:8080") -> Target:
    return Target(name="lab-web", kind=TargetKind.URL, address=address)


def _input_lines(execution: PluginExecution) -> list[str]:
    return execution.path("urls.txt").read_text().splitlines()


def test_build_command_writes_url_list_and_uses_json(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    cmd = plugin.build_command(_target(), {"paths": "/,/admin,/api/health"}, execution)
    assert cmd[0] == "httpx"
    assert "-json" in cmd and "-silent" in cmd
    assert "-l" in cmd
    assert _input_lines(execution) == [
        "http://lab-web:8080/",
        "http://lab-web:8080/admin",
        "http://lab-web:8080/api/health",
    ]


def test_default_probes_root(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    plugin.build_command(_target(), {}, execution)
    assert _input_lines(execution) == ["http://lab-web:8080/"]


def test_does_not_follow_redirects(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    cmd = plugin.build_command(_target(), {}, execution)
    assert "-follow-redirects" not in cmd and "-fr" not in cmd


def test_deduplicates_paths(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    plugin.build_command(_target(), {"paths": "/,/,/admin"}, execution)
    assert _input_lines(execution) == ["http://lab-web:8080/", "http://lab-web:8080/admin"]


def test_paths_file_is_merged(plugin: HttpxProbePlugin, execution: PluginExecution, tmp_path: Path) -> None:
    pf = tmp_path / "paths.txt"
    pf.write_text("/one\n/two\n\n")
    plugin.build_command(_target(), {"paths": "/", "paths_file": str(pf)}, execution)
    assert _input_lines(execution) == [
        "http://lab-web:8080/",
        "http://lab-web:8080/one",
        "http://lab-web:8080/two",
    ]


@pytest.mark.parametrize("path", ["admin", "//evil.example/x", "@evil/"])
def test_rejects_paths_that_could_leave_the_target(
    plugin: HttpxProbePlugin, execution: PluginExecution, path: str
) -> None:
    with pytest.raises(PluginError):
        plugin.build_command(_target(), {"paths": path}, execution)


def test_rejects_host_kind_target(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    with pytest.raises(PluginError, match="url"):
        plugin.build_command(Target(name="h", kind=TargetKind.HOST, address="lab"), {}, execution)


def test_rejects_non_integer_timeout(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    with pytest.raises(PluginError, match="timeout"):
        plugin.build_command(_target(), {"timeout": "soon"}, execution)


def test_missing_paths_file_errors(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    with pytest.raises(PluginError, match="paths_file"):
        plugin.build_command(_target(), {"paths_file": "/no/such/file.txt"}, execution)


def test_normalize_parses_jsonl_results_and_cleans_up(
    plugin: HttpxProbePlugin, execution: PluginExecution
) -> None:
    plugin.build_command(_target(), {"paths": "/,/admin"}, execution)
    raw = "\n".join(
        json.dumps(row)
        for row in [
            {"url": "http://lab-web:8080/", "status_code": 200, "title": "Home", "webserver": "nginx",
             "tech": ["Nginx"], "content_length": 12, "extra": "ignored"},
            {"url": "http://lab-web:8080/admin", "status_code": 302, "location": "/login"},
        ]
    )
    result = plugin.normalize(_target(), raw, "", execution)
    assert result["tool"] == "httpx"
    assert result["probed"] == 2
    assert result["results"][0]["title"] == "Home"
    assert result["results"][0]["tech"] == ["Nginx"]
    assert "extra" not in result["results"][0]  # only recorded fields are kept
    assert result["results"][1]["status_code"] == 302
    assert result["results"][1]["location"] == "/login"
    # no findings: httpx is a discovery/fingerprint sweep, like recon/web
    assert "_findings" not in result


def test_normalize_ignores_non_json_lines(plugin: HttpxProbePlugin, execution: PluginExecution) -> None:
    plugin.build_command(_target(), {}, execution)
    result = plugin.normalize(_target(), "warning: something\n{bad json\n", "", execution)
    assert result["probed"] == 0
    assert result["results"] == []


def test_version_command(plugin: HttpxProbePlugin) -> None:
    assert plugin.version_command() == ["httpx", "-version"]
