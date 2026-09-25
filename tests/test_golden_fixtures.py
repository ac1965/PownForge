"""Golden-file regression tests (refactor v3 §5): parses each plugin
against a real captured tool output stored as its own file under
tests/golden/, instead of an inline string literal in the test module.

This is a regression-prevention measure against *known* real output
shapes, not a substitute for actual hands-on real-machine verification
(docs/handbook.md §16) -- see docs/handbook.md §16 "golden file" for how
these were captured and how to add more.
"""

from __future__ import annotations

import json
from pathlib import Path

from pownforge.core.models import Target, TargetKind
from pownforge.plugins._trivy import findings_from_trivy_results
from pownforge.plugins.imagevuln import ImagevulnPlugin
from pownforge.plugins.network import NetworkPlugin
from pownforge.plugins.base import PluginExecution

GOLDEN_DIR = Path(__file__).parent / "golden"


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


# --- network (nmap) ---------------------------------------------------
# tests/golden/network/nmap_localhost.xml: `nmap -sV -Pn -p 3000 127.0.0.1`
# (nmap 7.991, macOS/Homebrew), captured 2026-09-25.


def test_network_plugin_parses_golden_nmap_xml(tmp_path: Path) -> None:
    plugin = NetworkPlugin()
    target = Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1")
    execution = _execution(tmp_path)
    xml_path = execution.path("nmap.xml")
    xml_path.write_bytes((GOLDEN_DIR / "network" / "nmap_localhost.xml").read_bytes())

    output = plugin.normalize(target, "", "", execution)

    assert output["hosts"][0]["address"] == "127.0.0.1"
    port = output["hosts"][0]["ports"][0]
    assert port["port"] == "3000"
    assert port["state"] == "open"
    assert port["service"] == "http"
    assert port["product"] == "Uvicorn"


# --- container (trivy image) -------------------------------------------
# tests/golden/container/trivy_alpine.json: `trivy image --scanners vuln
# -f json --severity CRITICAL alpine:3.10` (trivy, real DB), captured
# 2026-09-25. Real, complete, unmodified trivy output (not hand-trimmed) --
# filtered to CRITICAL only at capture time via trivy's own --severity flag
# to keep the file small, rather than post-hoc editing the JSON.


def test_trivy_findings_from_golden_container_json() -> None:
    data = json.loads((GOLDEN_DIR / "container" / "trivy_alpine.json").read_text())
    located_results = ((r.get("Target") or "alpine:3.10", r) for r in data["Results"])

    findings = findings_from_trivy_results(located_results)

    assert len(findings) == 1
    finding = findings[0]
    assert "CVE-2021-36159" in finding["title"]
    assert finding["severity"] == "critical"
    assert finding["native_severity"] == "CRITICAL"
    assert finding["cvss_score"] is not None
    assert finding["cvss_vector"] is not None


# --- imagevuln (grype) --------------------------------------------------
# tests/golden/imagevuln/grype_alpine.json: `grype alpine:3.10 -o json`,
# captured 2026-09-25, then trimmed to 2 of the real `matches` entries
# (CVE-2022-2068, CVE-2021-3711) -- each entry kept byte-for-byte as grype
# produced it (grype has no built-in output filter, so trimming the list
# is done post-hoc; no field within a kept entry is edited).


def test_imagevuln_plugin_parses_golden_grype_json(tmp_path: Path) -> None:
    plugin = ImagevulnPlugin()
    target = Target(name="alpine-image", kind=TargetKind.HOST, address="alpine:3.10")
    execution = _execution(tmp_path)
    execution.path("grype.json").write_bytes((GOLDEN_DIR / "imagevuln" / "grype_alpine.json").read_bytes())

    output = plugin.normalize(target, "", "", execution)

    assert len(output["matches"]) == 2
    findings_by_id = {f["title"].split(" in ")[0]: f for f in output["_findings"]}
    assert "CVE-2022-2068" in findings_by_id
    assert "CVE-2021-3711" in findings_by_id
    multi_cvss_finding = findings_by_id["CVE-2022-2068"]
    assert multi_cvss_finding["severity"] == "high"
    assert multi_cvss_finding["cvss_score"] is not None
    assert multi_cvss_finding["native_severity"] == "High"
