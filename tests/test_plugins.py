from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError
from pownforge.plugins.network import NetworkPlugin
from pownforge.plugins.web import WebPlugin

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_network_plugin_normalizes_nmap_xml(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = NetworkPlugin()
    target = Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1")
    monkeypatch.setattr(NetworkPlugin, "check", lambda self: True)

    command = plugin.build_command(target, {})
    xml_path = Path(command[command.index("-oX") + 1])
    xml_path.write_text(NMAP_XML)

    output = plugin.normalize(target, "", "")

    assert output["hosts"][0]["address"] == "127.0.0.1"
    assert output["hosts"][0]["ports"][0]["service"] == "http"
    assert output["hosts"][0]["ports"][0]["state"] == "open"
    assert not xml_path.exists()


def test_network_plugin_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = NetworkPlugin()
    monkeypatch.setattr(NetworkPlugin, "check", lambda self: False)
    target = Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1")
    with pytest.raises(PluginError):
        plugin.build_command(target, {})


FFUF_JSON = json.dumps(
    {
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "url": "http://lab-web:3000/admin",
                "status": 200,
                "length": 512,
                "words": 10,
            }
        ]
    }
)


def test_web_plugin_normalizes_ffuf_json(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = WebPlugin()
    target = Target(name="lab-web", kind=TargetKind.URL, address="http://lab-web:3000")
    monkeypatch.setattr(WebPlugin, "check", lambda self: True)

    command = plugin.build_command(target, {"wordlist": "wordlist.txt"})
    json_path = Path(command[command.index("-o") + 1])
    json_path.write_text(FFUF_JSON)

    output = plugin.normalize(target, "", "")

    assert output["hits"][0]["path"] == "admin"
    assert output["hits"][0]["status"] == 200
    assert not json_path.exists()


def test_web_plugin_requires_wordlist(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = WebPlugin()
    monkeypatch.setattr(WebPlugin, "check", lambda self: True)
    target = Target(name="lab-web", kind=TargetKind.URL, address="http://lab-web:3000")
    with pytest.raises(PluginError):
        plugin.build_command(target, {})


def test_network_plugin_version_command() -> None:
    assert NetworkPlugin().version_command() == ["nmap", "--version"]


def test_web_plugin_version_command() -> None:
    assert WebPlugin().version_command() == ["ffuf", "-V"]
