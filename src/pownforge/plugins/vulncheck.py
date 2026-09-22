from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from pownforge.core.models import Target
from pownforge.plugins.base import Plugin, PluginError

# Only nmap NSE scripts nmap itself categorizes as both "vuln" and "safe"
# (never "exploit"/"intrusive"/"dos"/"brute") are eligible. That excludes,
# by design, scripts like http-shellshock or ftp-vsftpd-backdoor which run a
# command or open a shell on the target by default -- this plugin verifies
# a known CVE's presence on a single already-authorized target, the same
# way sqlmap proves SQL injection, and never escalates beyond that (no OS
# command execution, no lateral movement). See docs/handbook.md §6.
_ALLOWED_SCRIPTS: dict[str, str] = {
    "ssl-heartbleed": "OpenSSL Heartbleed (CVE-2014-0160)",
    "ssl-poodle": "SSLv3 POODLE (CVE-2014-3566)",
    "ssl-ccs-injection": "OpenSSL ChangeCipherSpec injection (CVE-2014-0224)",
    "tls-ticketbleed": "TLS session ticket memory disclosure (CVE-2016-9244)",
    "smb-vuln-ms17-010": "SMB EternalBlue (CVE-2017-0143 through 0148)",
    "smb-double-pulsar-backdoor": "SMB DoublePulsar backdoor presence",
    "http-vuln-cve2010-0738": "JBoss JMX console authentication bypass (CVE-2010-0738)",
    "http-vuln-cve2011-3192": "Apache Range header DoS (CVE-2011-3192)",
    "http-vuln-cve2014-2126": "Cisco ASA VPN privilege escalation (CVE-2014-2126)",
    "http-vuln-cve2014-2127": "Cisco ASA VPN SQL injection (CVE-2014-2127)",
    "http-vuln-cve2014-2128": "Cisco ASA VPN authentication bypass (CVE-2014-2128)",
    "http-vuln-cve2014-2129": "Cisco ASA VPN ACL bypass (CVE-2014-2129)",
    "http-vuln-cve2015-1635": "Windows HTTP.sys remote code execution / MS15-034 (CVE-2015-1635)",
    "http-vuln-cve2017-1001000": "WordPress REST API content injection (CVE-2017-1001000)",
    "rsa-vuln-roca": "RSA key generation weakness / ROCA (CVE-2017-15361)",
}

_SEVERITY_BY_SCRIPT: dict[str, str] = {
    "ssl-heartbleed": "high",
    "ssl-poodle": "medium",
    "ssl-ccs-injection": "high",
    "tls-ticketbleed": "medium",
    "smb-vuln-ms17-010": "critical",
    "smb-double-pulsar-backdoor": "critical",
    "http-vuln-cve2010-0738": "high",
    "http-vuln-cve2011-3192": "medium",
    "http-vuln-cve2014-2126": "high",
    "http-vuln-cve2014-2127": "high",
    "http-vuln-cve2014-2128": "high",
    "http-vuln-cve2014-2129": "high",
    "http-vuln-cve2015-1635": "critical",
    "http-vuln-cve2017-1001000": "high",
    "rsa-vuln-roca": "medium",
}


class VulncheckPlugin(Plugin):
    name = "vulncheck"
    version = "0.1.0"
    description = (
        "Single-target verification of a specific known CVE via one of nmap's "
        "non-intrusive 'vuln safe' NSE scripts (detection only, never OS command "
        "execution or lateral movement)."
    )
    required_tool = "nmap"
    expected_kind = None  # like NetworkPlugin, works against a host or a url's host

    def __init__(self) -> None:
        self._xml_path: Path | None = None

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["nmap", "--version"]

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")

        script = options.get("script")
        if not script:
            raise PluginError(
                "vulncheck plugin requires --option script=<name>, one of: "
                + ", ".join(sorted(_ALLOWED_SCRIPTS))
            )
        if script not in _ALLOWED_SCRIPTS:
            raise PluginError(
                f"script '{script}' is not on the vulncheck allowlist (only nmap NSE scripts "
                "categorized 'vuln'+'safe' are permitted, never 'exploit'/'intrusive'); allowed: "
                + ", ".join(sorted(_ALLOWED_SCRIPTS))
            )

        fd, raw_path = tempfile.mkstemp(prefix="pownforge-vulncheck-", suffix=".xml")
        os.close(fd)
        self._xml_path = Path(raw_path)

        args = [
            "nmap",
            "-Pn",
            "--script",
            script,
            "--script-args",
            "vulns.showall",
            "-oX",
            str(self._xml_path),
        ]
        if port := options.get("port"):
            args += ["-p", str(port)]
        args.append(target.address)
        return args

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        xml_path, self._xml_path = self._xml_path, None
        if xml_path is not None and xml_path.exists():
            try:
                results = self._parse_xml(xml_path)
            finally:
                xml_path.unlink(missing_ok=True)

        return {
            "target": target.address,
            "tool": "nmap",
            "results": results,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            # Only a result whose script actually reported "VULNERABLE" (not
            # "NOT VULNERABLE"/"LIKELY VULNERABLE"-as-unclear) becomes a
            # candidate Finding -- see _is_vulnerable_state().
            "_findings": [
                {
                    "title": _ALLOWED_SCRIPTS.get(result["script"], result["script"]),
                    "severity": _SEVERITY_BY_SCRIPT.get(result["script"], "medium"),
                    "detail": result["detail"],
                }
                for result in results
                if _is_vulnerable_state(result["state"])
            ],
        }

    @staticmethod
    def _parse_xml(xml_path: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            root = ElementTree.parse(xml_path).getroot()
        except ElementTree.ParseError:
            return results

        # Most scripts here (ssl-*, http-vuln-*) are portrule-based and land
        # under <port>, but some (smb-vuln-ms17-010, smb-double-pulsar-backdoor)
        # are hostrule-based and land under <hostscript> instead, with no
        # <port> ancestor at all -- both must be checked or those scripts'
        # results are silently dropped even though nmap did run them.
        for port_el in root.findall(".//port"):
            for script_el in port_el.findall("script"):
                results.append(_parse_script_result(script_el, port=port_el.get("portid")))
        for script_el in root.findall(".//hostscript/script"):
            results.append(_parse_script_result(script_el, port=None))
        return results


def _parse_script_result(script_el: ElementTree.Element, port: str | None) -> dict[str, Any]:
    script_id = script_el.get("id", "")
    output = script_el.get("output", "").strip()
    state = None
    title = None
    table_el = script_el.find("table")
    if table_el is not None:
        for elem in table_el.findall("elem"):
            key = elem.get("key")
            if key == "state":
                state = (elem.text or "").strip()
            elif key == "title":
                title = (elem.text or "").strip()
    return {
        "script": script_id,
        "port": port,
        "state": state or "UNKNOWN",
        "detail": title or output,
    }


def _is_vulnerable_state(state: str) -> bool:
    normalized = state.upper()
    return "VULNERABLE" in normalized and "NOT VULNERABLE" not in normalized
