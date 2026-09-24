from __future__ import annotations

import json
import re
import shutil
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# testssl.sh's own severity vocabulary. "OK"/"INFO"/"DEBUG" are not findings
# (a passed check or informational context, not a problem) -- see
# _parse_report(). Anything else unrecognized falls back to "info" via
# .get(), same fallback coerce_finding() (core/finding_utils.py) applies.
_SEVERITY_BY_TESTSSL_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "info",
}
_NON_FINDING_SEVERITIES = frozenset({"OK", "INFO", "DEBUG"})
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
_VERSION_LINE = re.compile(r"testssl\.sh version ([\w.]+)")


class TlsPlugin(Plugin):
    name = "tls"
    version = "0.1.0"
    description = "TLS/SSL configuration, certificate, and cipher weakness assessment via testssl.sh."
    required_tool = "testssl.sh"
    expected_kind = TargetKind.HOST
    kind_hint = "address is host or host:port (port defaults to 443, e.g. lab-web or lab-web:8443)."

    options_schema = (
        PluginOption(name="port", description="Port to connect to if not already in the address.", default="443"),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        # --version can't be combined with --quiet/--color (testssl.sh
        # refuses to start), so its banner output is unavoidable --
        # parse_version_output() below extracts the real version from it.
        return [self.required_tool, "--version"]

    def parse_version_output(self, stdout: str, stderr: str) -> str | None:
        clean = _ANSI_ESCAPE.sub("", stdout + "\n" + stderr)
        match = _VERSION_LINE.search(clean)
        return match.group(1) if match else super().parse_version_output(stdout, stderr)

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        address = target.address
        if ":" not in address:
            address = f"{address}:{options.get('port', '443')}"

        report_path = execution.path("testssl.json")
        return [
            "testssl.sh",
            "--quiet",
            "--color",
            "0",
            "--jsonfile",
            str(report_path),
            "--connect-timeout",
            "5",
            "--openssl-timeout",
            "5",
            # Protocols, server defaults/certificate info, forward secrecy --
            # a fast, informative subset (real-machine verified <2s against
            # a live host). testssl.sh's own default ("everything except
            # -E/-g", incl. exhaustive per-cipher enumeration via -s) took
            # well over a minute in the same test, which doesn't fit a
            # "minimal starting point" default -- see docs/handbook.md §6.
            "-p",
            "-S",
            "-f",
            address,
        ]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        report_path = execution.path("testssl.json")
        checks: list[dict[str, Any]] = []
        if report_path.exists():
            checks = self._parse_report(report_path)

        return {
            "target": target.address,
            "tool": "testssl.sh",
            "checks": checks,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [
                {
                    "title": f"{check['id']}: {check['finding']}",
                    "severity": _SEVERITY_BY_TESTSSL_SEVERITY.get(check["severity"], "info"),
                    "detail": f"{check['ip']}:{check['port']} -- {check['finding']}",
                }
                for check in checks
                if check["severity"] not in _NON_FINDING_SEVERITIES
            ],
        }

    @staticmethod
    def _parse_report(report_path) -> list[dict[str, Any]]:
        try:
            data = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []

        checks: list[dict[str, Any]] = []
        for raw in data:
            if not isinstance(raw, dict):
                continue
            checks.append(
                {
                    "id": raw.get("id", ""),
                    "ip": raw.get("ip", ""),
                    "port": raw.get("port", ""),
                    "severity": raw.get("severity", "INFO"),
                    "finding": raw.get("finding", ""),
                }
            )
        return checks
