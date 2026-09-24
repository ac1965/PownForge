from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.identity import IdentityPlugin

BASE = "http://lab-idp:8080/realms/lab"


@pytest.fixture
def plugin(monkeypatch: pytest.MonkeyPatch) -> IdentityPlugin:
    monkeypatch.setattr("pownforge.plugins.identity.shutil.which", lambda _: "/usr/bin/curl")
    return IdentityPlugin()


@pytest.fixture
def execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target(address: str = BASE) -> Target:
    return Target(name="lab-idp", kind=TargetKind.URL, address=address)


def _response(doc: dict, status: str = "200 OK") -> str:
    return f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\r\n{json.dumps(doc)}"


def _titles(result: dict) -> set[str]:
    return {f["title"] for f in result["_findings"]}


def test_build_command_fetches_openid_configuration_once(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    cmd = plugin.build_command(_target(), {}, execution)
    assert cmd[0] == "curl"
    assert cmd[-1] == f"{BASE}/.well-known/openid-configuration"
    assert "-L" not in cmd and "-X" not in cmd
    assert cmd[cmd.index("--proto") + 1] == "=http,https"
    assert not any(part.lower().startswith("authorization") for part in cmd)


def test_build_command_supports_rfc8414_document(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    cmd = plugin.build_command(_target(), {"document": "oauth-authorization-server"}, execution)
    assert cmd[-1] == f"{BASE}/.well-known/oauth-authorization-server"


def test_build_command_rejects_arbitrary_document(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    with pytest.raises(PluginError, match="document"):
        plugin.build_command(_target(), {"document": "../admin"}, execution)


def test_build_command_rejects_host_kind(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    with pytest.raises(PluginError, match="url"):
        plugin.build_command(Target(name="h", kind=TargetKind.HOST, address="lab-idp"), {}, execution)


def test_normalize_records_selected_metadata(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    plugin.build_command(_target(), {}, execution)
    doc = {
        "issuer": BASE,
        "token_endpoint": f"{BASE}/protocol/openid-connect/token",
        "jwks_uri": f"{BASE}/protocol/openid-connect/certs",
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["plain", "S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "unrelated_vendor_field": "x",
    }
    result = plugin.normalize(_target(), _response(doc), "", execution)
    assert result["metadata_found"] is True
    assert result["url"].endswith("/.well-known/openid-configuration")
    assert result["metadata"]["issuer"] == BASE
    assert "unrelated_vendor_field" not in result["metadata"]
    # lab host over http is only flagged as plain-http, nothing else
    assert _titles(result) == {"Discovery document advertises plain-http endpoints"}


def test_normalize_flags_weak_configuration(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    target = _target("https://idp.lab")
    plugin.build_command(target, {}, execution)
    doc = {
        "issuer": "https://other.example",
        "id_token_signing_alg_values_supported": ["RS256", "none"],
        "grant_types_supported": ["authorization_code", "implicit", "password"],
        "code_challenge_methods_supported": ["plain"],
    }
    titles = _titles(plugin.normalize(target, _response(doc), "", execution))
    assert any("issuer differs" in t for t in titles)
    assert any("alg 'none'" in t for t in titles)
    assert any("Implicit flow" in t for t in titles)
    assert any("password credentials" in t for t in titles)
    assert any("PKCE S256" in t for t in titles)


def test_normalize_non_200_or_non_json_yields_no_findings(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    assert plugin.normalize(_target(), _response({}, "404 Not Found"), "", execution)["_findings"] == []
    html = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
    result = plugin.normalize(_target(), html, "", execution)
    assert result["metadata_found"] is False
    assert result["_findings"] == []


def test_normalize_without_response(plugin: IdentityPlugin, execution: PluginExecution) -> None:
    result = plugin.normalize(_target(), "", "curl: (7) Failed to connect", execution)
    assert result["status"] is None
    assert result["_findings"] == []
