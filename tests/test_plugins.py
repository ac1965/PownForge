from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError
from pownforge.plugins.kubernetes import KubernetesPlugin
from pownforge.plugins.network import NetworkPlugin
from pownforge.plugins.nuclei import NucleiPlugin
from pownforge.plugins.sqlmap import SqlmapPlugin
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


# Captured verbatim (trimmed of [INFO]/timestamp noise) from a real
# `sqlmap --url http://127.0.0.1:.../product?id=1 --batch --risk 1 --level 1`
# run against a deliberately vulnerable local Flask/sqlite endpoint
# (sqlmap 1.10.9). See docs/sqlmap.md.
SQLMAP_STDOUT_INJECTABLE = """\
sqlmap identified the following injection point(s) with a total of 52 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8652=8652

    Type: error-based
    Title: SQLite >= 3.9 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON path)
    Payload: id=1 AND 5209=JSON_EXTRACT(CHAR(123,125),CHAR(113,118,122,98,113)||(SELECT (CASE WHEN (5209=5209) THEN 1 ELSE 0 END))||CHAR(113,120,106,120,113))

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: id=1 AND 7691=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT CHAR(113,118,122,98,113)||CHAR(83,122,78,67,121,112,84,105,70,104,75,84,111,79,73,86,69,100,69,74,67,117,69,65,78,114,120,87,102,107,107,81,104,73,87,112,103,90,71,112)||CHAR(113,120,106,120,113),NULL,NULL-- lqjV
---
the back-end DBMS is SQLite
back-end DBMS: SQLite
"""

SQLMAP_STDOUT_NOT_INJECTABLE = """\
testing 'Generic UNION query (NULL) - 1 to 10 columns'
GET parameter 'safe' does not seem to be injectable
all tested parameters do not appear to be injectable. Try to increase values \
for '--level'/'--risk' options if you wish to perform more tests.
"""


def test_sqlmap_plugin_parses_injection_points_and_findings() -> None:
    plugin = SqlmapPlugin()
    target = Target(name="sqlmap-lab", kind=TargetKind.URL, address="http://127.0.0.1:15000/product?id=1")
    output = plugin.normalize(target, SQLMAP_STDOUT_INJECTABLE, "")

    assert output["dbms"] == "SQLite"
    assert len(output["injection_points"]) == 1
    point = output["injection_points"][0]
    assert point["parameter"] == "id"
    assert point["method"] == "GET"
    assert [t["type"] for t in point["techniques"]] == [
        "boolean-based blind",
        "error-based",
        "time-based blind",
        "UNION query",
    ]

    findings = output["_findings"]
    assert len(findings) == 4
    assert all(f["severity"] == "critical" for f in findings)
    assert "id (GET)" in findings[0]["title"]
    assert "AND 8652=8652" in findings[0]["detail"]


def test_sqlmap_plugin_no_findings_when_not_injectable() -> None:
    plugin = SqlmapPlugin()
    target = Target(name="sqlmap-lab", kind=TargetKind.URL, address="http://127.0.0.1:15000/product?id=1&safe=x")
    output = plugin.normalize(target, SQLMAP_STDOUT_NOT_INJECTABLE, "")
    assert output["injection_points"] == []
    assert output["_findings"] == []
    assert output["dbms"] is None


def test_sqlmap_plugin_requires_url_target(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = SqlmapPlugin()
    monkeypatch.setattr(SqlmapPlugin, "check", lambda self: True)
    target = Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1")
    with pytest.raises(PluginError):
        plugin.build_command(target, {})


def test_sqlmap_plugin_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = SqlmapPlugin()
    monkeypatch.setattr(SqlmapPlugin, "check", lambda self: False)
    target = Target(name="sqlmap-lab", kind=TargetKind.URL, address="http://127.0.0.1:15000/product?id=1")
    with pytest.raises(PluginError):
        plugin.build_command(target, {})


@pytest.mark.parametrize(
    "denied_option",
    [
        "os-shell",
        "os-pwn",
        "os-cmd",
        "file-read",
        "file-write",
        "file-dest",
        "sql-shell",
        "shell",
        "wizard",
        "eval",
        "tamper",
        "answers",
        "c",
        "configfile",
        "reg-read",
    ],
)
def test_sqlmap_plugin_rejects_denied_options(monkeypatch: pytest.MonkeyPatch, denied_option: str) -> None:
    plugin = SqlmapPlugin()
    monkeypatch.setattr(SqlmapPlugin, "check", lambda self: True)
    target = Target(name="sqlmap-lab", kind=TargetKind.URL, address="http://127.0.0.1:15000/product?id=1")
    with pytest.raises(PluginError):
        plugin.build_command(target, {denied_option: "true"})


def test_sqlmap_plugin_rejects_denied_option_with_leading_dashes(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = SqlmapPlugin()
    monkeypatch.setattr(SqlmapPlugin, "check", lambda self: True)
    target = Target(name="sqlmap-lab", kind=TargetKind.URL, address="http://127.0.0.1:15000/product?id=1")
    with pytest.raises(PluginError):
        plugin.build_command(target, {"--os-shell": "true"})


def test_sqlmap_plugin_build_command_defaults_and_options(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = SqlmapPlugin()
    monkeypatch.setattr(SqlmapPlugin, "check", lambda self: True)
    target = Target(name="sqlmap-lab", kind=TargetKind.URL, address="http://127.0.0.1:15000/product?id=1")

    command = plugin.build_command(target, {})
    assert "--risk" in command and "1" in command
    assert "--level" in command and "1" in command
    assert "--batch" in command
    assert "--output-dir" in command
    output_dir = Path(command[command.index("--output-dir") + 1])
    assert output_dir.is_dir()
    plugin.normalize(target, "", "")  # cleans up the temp --output-dir
    assert not output_dir.exists()

    command = plugin.build_command(target, {"risk": "2", "level": "3", "dump": "true"})
    assert command[command.index("--risk") + 1] == "2"
    assert command[command.index("--level") + 1] == "3"
    assert "--dump" in command
    plugin.normalize(target, "", "")  # cleans up the second temp --output-dir


def test_sqlmap_plugin_version_command() -> None:
    assert SqlmapPlugin().version_command() == ["sqlmap", "--version"]
