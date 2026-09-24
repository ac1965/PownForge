from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.api import ApiPlugin
from pownforge.plugins.base import PluginError, PluginExecution


@pytest.fixture
def plugin(monkeypatch: pytest.MonkeyPatch) -> ApiPlugin:
    monkeypatch.setattr("pownforge.plugins.api.shutil.which", lambda _: "/usr/bin/curl")
    return ApiPlugin()


@pytest.fixture
def execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target(address: str = "http://lab-api:3000") -> Target:
    return Target(name="lab-api", kind=TargetKind.URL, address=address)


def test_build_command_defaults_to_get_root_without_following_redirects(
    plugin: ApiPlugin, execution: PluginExecution
) -> None:
    cmd = plugin.build_command(_target(), {}, execution)
    assert cmd[-1] == "http://lab-api:3000/"
    assert cmd[cmd.index("-X") + 1] == "GET"
    assert "-L" not in cmd and "--location" not in cmd
    assert cmd[cmd.index("--proto") + 1] == "=http,https"


def test_build_command_appends_path(plugin: ApiPlugin, execution: PluginExecution) -> None:
    cmd = plugin.build_command(_target("http://lab-api:3000/"), {"path": "/rest/products?q=1"}, execution)
    assert cmd[-1] == "http://lab-api:3000/rest/products?q=1"


def test_head_uses_dash_i_not_dash_x(plugin: ApiPlugin, execution: PluginExecution) -> None:
    cmd = plugin.build_command(_target(), {"method": "head"}, execution)
    assert "-I" in cmd and "-X" not in cmd


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_rejects_state_changing_methods(plugin: ApiPlugin, execution: PluginExecution, method: str) -> None:
    with pytest.raises(PluginError, match="only allows"):
        plugin.build_command(_target(), {"method": method}, execution)


@pytest.mark.parametrize("path", ["rest", "//evil.example/x", "@evil.example/"])
def test_rejects_paths_that_could_leave_the_target(
    plugin: ApiPlugin, execution: PluginExecution, path: str
) -> None:
    with pytest.raises(PluginError):
        plugin.build_command(_target(), {"path": path}, execution)


def test_rejects_host_kind_target(plugin: ApiPlugin, execution: PluginExecution) -> None:
    with pytest.raises(PluginError, match="url"):
        plugin.build_command(Target(name="h", kind=TargetKind.HOST, address="lab"), {}, execution)


def test_rejects_non_integer_timeout(plugin: ApiPlugin, execution: PluginExecution) -> None:
    with pytest.raises(PluginError, match="timeout"):
        plugin.build_command(_target(), {"timeout": "soon"}, execution)


def test_normalize_parses_status_headers_body_and_findings(plugin: ApiPlugin, execution: PluginExecution) -> None:
    plugin.build_command(_target(), {"path": "/api"}, execution)
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "X-Powered-By: Express 4.17.1\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n"
        '{"ok":true}'
    )
    result = plugin.normalize(_target(), raw, "", execution)
    assert result["status"] == 200
    assert result["reason"] == "OK"
    assert result["url"] == "http://lab-api:3000/api"
    assert result["headers"]["content-type"] == "application/json"
    assert result["body"] == '{"ok":true}'
    titles = {f["title"] for f in result["_findings"]}
    assert "X-Content-Type-Options header missing" in titles
    assert "Version disclosed in x-powered-by header" in titles
    assert any("CORS" in t for t in titles)
    # HSTS only matters over https
    assert not any("Strict-Transport-Security" in t for t in titles)


def test_normalize_flags_missing_hsts_on_https(plugin: ApiPlugin, execution: PluginExecution) -> None:
    target = _target("https://lab-api")
    plugin.build_command(target, {}, execution)
    result = plugin.normalize(target, "HTTP/2 204\r\nx-content-type-options: nosniff\r\n\r\n", "", execution)
    assert result["status"] == 204
    assert any("Strict-Transport-Security" in f["title"] for f in result["_findings"])


def test_normalize_skips_interim_100_continue(plugin: ApiPlugin, execution: PluginExecution) -> None:
    raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\nnope"
    result = plugin.normalize(_target(), raw, "", execution)
    assert result["status"] == 404
    assert result["body"] == "nope"


def test_normalize_without_response_yields_no_findings(plugin: ApiPlugin, execution: PluginExecution) -> None:
    result = plugin.normalize(_target(), "", "curl: (7) Failed to connect", execution)
    assert result["status"] is None
    assert result["_findings"] == []


def test_normalize_truncates_large_body(plugin: ApiPlugin, execution: PluginExecution) -> None:
    result = plugin.normalize(_target(), "HTTP/1.1 200 OK\r\n\r\n" + "x" * 30_000, "", execution)
    assert result["body_truncated"] is True
    assert len(result["body"]) == 20_000
