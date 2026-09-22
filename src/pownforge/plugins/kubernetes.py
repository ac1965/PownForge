from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pownforge.core.models import Target
from pownforge.plugins.base import Plugin, PluginError


class KubernetesPlugin(Plugin):
    name = "kubernetes"
    version = "0.1.0"
    description = "Cluster misconfiguration, RBAC, and workload vulnerability scanning via trivy k8s."
    required_tool = "trivy"

    def __init__(self) -> None:
        self._json_path: Path | None = None

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["trivy", "--version"]

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")

        fd, raw_path = tempfile.mkstemp(prefix="pownforge-trivy-", suffix=".json")
        os.close(fd)
        self._json_path = Path(raw_path)

        # target.address holds a kubeconfig context name (e.g.
        # "kind-pownforge-lab"), not a host/URL — trivy reads the matching
        # cluster connection details from the ambient kubeconfig itself.
        args = [
            "trivy",
            "k8s",
            target.address,
            "-f",
            "json",
            "-o",
            str(self._json_path),
            "--report",
            "all",
            "--no-progress",
        ]
        if namespaces := options.get("namespaces"):
            args += ["--include-namespaces", str(namespaces)]
        if severity := options.get("severity"):
            args += ["--severity", str(severity)]
        return args

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        resources: list[dict[str, Any]] = []
        json_path, self._json_path = self._json_path, None
        if json_path is not None and json_path.exists():
            try:
                resources = self._parse_json(json_path)
            finally:
                json_path.unlink(missing_ok=True)

        return {
            "target": target.address,
            "tool": "trivy",
            "resources": resources,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": self._extract_findings(resources),
        }

    @staticmethod
    def _parse_json(json_path: Path) -> list[dict[str, Any]]:
        try:
            data = json.loads(json_path.read_text())
        except json.JSONDecodeError:
            return []
        return data.get("Resources") or []

    @staticmethod
    def _extract_findings(resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for resource in resources:
            location = "/".join(
                part
                for part in (resource.get("Namespace"), resource.get("Kind"), resource.get("Name"))
                if part
            )
            for result in resource.get("Results") or []:
                for m in result.get("Misconfigurations") or []:
                    findings.append(
                        {
                            "title": f"[{m.get('ID', '?')}] {m.get('Title') or 'misconfiguration'}",
                            # trivy uses UPPERCASE severities (HIGH, MEDIUM,
                            # ...); our Finding.severity enum is lowercase.
                            # coerce_finding() falls back to "info" for
                            # anything that still doesn't match (e.g.
                            # trivy's "UNKNOWN").
                            "severity": (m.get("Severity") or "info").lower(),
                            "detail": f"{location}: {m.get('Message') or m.get('Description') or ''}",
                        }
                    )
                for v in result.get("Vulnerabilities") or []:
                    findings.append(
                        {
                            "title": (
                                f"[{v.get('VulnerabilityID', '?')}] "
                                f"{v.get('Title') or v.get('PkgName') or 'vulnerability'}"
                            ),
                            "severity": (v.get("Severity") or "info").lower(),
                            "detail": f"{location}: {v.get('Description') or ''}",
                        }
                    )
                for s in result.get("Secrets") or []:
                    findings.append(
                        {
                            "title": f"[{s.get('RuleID', '?')}] {s.get('Title') or 'exposed secret'}",
                            "severity": (s.get("Severity") or "info").lower(),
                            "detail": f"{location}: {s.get('Match') or ''}",
                        }
                    )
        return findings
