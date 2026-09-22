from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError
from pownforge.plugins.kubernetes import KubernetesPlugin
from pownforge.plugins.network import NetworkPlugin
from pownforge.plugins.nuclei import NucleiPlugin
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


NUCLEI_JSONL = "\n".join(
    [
        json.dumps(
            {
                "template-id": "exposed-panel",
                "info": {
                    "name": "Exposed Admin Panel",
                    "severity": "medium",
                    "description": "An admin panel was found exposed.",
                },
                "matched-at": "http://lab-web:3000/admin",
                "host": "lab-web",
            }
        ),
        json.dumps(
            {
                "template-id": "weird-severity",
                "info": {"name": "Weird severity template", "severity": "unknown"},
                "matched-at": "http://lab-web:3000/x",
            }
        ),
        "",  # trailing blank line should be skipped
    ]
)


def test_nuclei_plugin_normalizes_jsonl_into_matches_and_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin = NucleiPlugin()
    target = Target(name="lab-web", kind=TargetKind.URL, address="http://lab-web:3000")
    monkeypatch.setattr(NucleiPlugin, "check", lambda self: True)

    command = plugin.build_command(target, {"tags": "exposures", "severity": "medium,high"})
    assert "-tags" in command and "exposures" in command
    assert "-severity" in command and "medium,high" in command
    jsonl_path = Path(command[command.index("-o") + 1])
    jsonl_path.write_text(NUCLEI_JSONL)

    output = plugin.normalize(target, "", "")

    assert len(output["matches"]) == 2
    assert output["matches"][0]["name"] == "Exposed Admin Panel"
    assert not jsonl_path.exists()

    findings = output["_findings"]
    assert findings[0]["title"] == "Exposed Admin Panel"
    assert findings[0]["severity"] == "medium"
    assert findings[1]["title"] == "Weird severity template"
    assert findings[1]["severity"] == "unknown"  # ScanRunner/coerce_finding handles the fallback


def test_nuclei_plugin_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = NucleiPlugin()
    monkeypatch.setattr(NucleiPlugin, "check", lambda self: False)
    target = Target(name="lab-web", kind=TargetKind.URL, address="http://lab-web:3000")
    with pytest.raises(PluginError):
        plugin.build_command(target, {})


def test_nuclei_plugin_version_command() -> None:
    assert NucleiPlugin().version_command() == ["nuclei", "-version"]


def test_nuclei_plugin_parses_version_from_noisy_stderr() -> None:
    stderr = (
        "WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or "
        "(go1.20~1.26 and arm64 CPU), but your environment is not suitable "
        "and will fallback to encoding/json\n"
        "[\x1b[1;34mINF\x1b[0m] Nuclei Engine Version: v3.11.1\n"
        "[\x1b[1;34mINF\x1b[0m] Nuclei Config Directory: /root/.config/nuclei\n"
    )
    version = NucleiPlugin().parse_version_output("", stderr)
    assert version == "Nuclei Engine Version: v3.11.1"


def test_nuclei_plugin_falls_back_to_default_parsing_when_no_version_line() -> None:
    version = NucleiPlugin().parse_version_output("", "some unrelated output\nmore\n")
    assert version == "some unrelated output"


# Shape captured from a real `trivy k8s <context> -f json` run against a
# local kind cluster (see docs/walkthrough.md).
TRIVY_K8S_JSON = json.dumps(
    {
        "ClusterName": "kind-pownforge-lab",
        "Resources": [
            {
                "Namespace": "kube-system",
                "Kind": "DaemonSet",
                "Name": "kindnet",
                "Results": [
                    {
                        "Target": "DaemonSet/kindnet",
                        "Class": "config",
                        "Misconfigurations": [
                            {
                                "ID": "KSV-0001",
                                "Title": "Can elevate its own privileges",
                                "Message": "Container 'kindnet-cni' should set allowPrivilegeEscalation to false",
                                "Severity": "MEDIUM",
                            }
                        ],
                    }
                ],
            },
            {
                "Namespace": "kube-system",
                "Kind": "Deployment",
                "Name": "coredns",
                "Results": [
                    {
                        "Target": "coredns (golang)",
                        "Class": "lang-pkgs",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-28452",
                                "Title": "CoreDNS vulnerable to TuDoor Attacks",
                                "Description": "An issue was discovered in CoreDNS...",
                                "Severity": "HIGH",
                            },
                            {
                                "VulnerabilityID": "CVE-9999-0000",
                                "Title": "made up unknown-severity CVE",
                                "Severity": "UNKNOWN",
                            },
                        ],
                    }
                ],
            },
        ],
    }
)


def test_kubernetes_plugin_normalizes_trivy_json(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = KubernetesPlugin()
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-pownforge-lab")
    monkeypatch.setattr(KubernetesPlugin, "check", lambda self: True)

    command = plugin.build_command(target, {"severity": "MEDIUM,HIGH,CRITICAL"})
    assert command[2] == "kind-pownforge-lab"  # context is positional, not a flag
    assert "--severity" in command and "MEDIUM,HIGH,CRITICAL" in command
    json_path = Path(command[command.index("-o") + 1])
    json_path.write_text(TRIVY_K8S_JSON)

    output = plugin.normalize(target, "", "")

    assert len(output["resources"]) == 2
    assert not json_path.exists()

    findings = output["_findings"]
    assert len(findings) == 3
    misconfig = next(f for f in findings if "KSV-0001" in f["title"])
    assert misconfig["severity"] == "medium"
    assert "kube-system/DaemonSet/kindnet" in misconfig["detail"]

    vuln = next(f for f in findings if "CVE-2023-28452" in f["title"])
    assert vuln["severity"] == "high"

    unknown_sev = next(f for f in findings if "CVE-9999-0000" in f["title"])
    assert unknown_sev["severity"] == "unknown"  # coerce_finding() handles the fallback to info


def test_kubernetes_plugin_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = KubernetesPlugin()
    monkeypatch.setattr(KubernetesPlugin, "check", lambda self: False)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-pownforge-lab")
    with pytest.raises(PluginError):
        plugin.build_command(target, {})


def test_kubernetes_plugin_version_command() -> None:
    assert KubernetesPlugin().version_command() == ["trivy", "--version"]
