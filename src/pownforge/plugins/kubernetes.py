from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins._trivy import findings_from_trivy_results
from pownforge.plugins.base import Plugin, PluginError, PluginExecution


class KubernetesPlugin(Plugin):
    name = "kubernetes"
    version = "0.1.0"
    description = "Cluster misconfiguration, RBAC, and workload vulnerability scanning via trivy k8s."
    required_tool = "trivy"
    expected_kind = TargetKind.HOST
    kind_hint = "address should be a kubeconfig context name, e.g. kind-pownforge-lab."

    options_schema = (
        PluginOption(name="namespaces", description="trivy --include-namespaces, comma-separated."),
        PluginOption(name="severity", description="trivy --severity, e.g. CRITICAL,HIGH."),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["trivy", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        json_path = execution.path("trivy-k8s.json")

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
            str(json_path),
            "--report",
            "all",
            "--no-progress",
        ]
        if namespaces := options.get("namespaces"):
            args += ["--include-namespaces", str(namespaces)]
        if severity := options.get("severity"):
            args += ["--severity", str(severity)]
        return args

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        resources: list[dict[str, Any]] = []
        json_path = execution.path("trivy-k8s.json")
        if json_path.exists():
            resources = self._parse_json(json_path)

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
        located_results = (
            (
                "/".join(
                    part
                    for part in (resource.get("Namespace"), resource.get("Kind"), resource.get("Name"))
                    if part
                ),
                result,
            )
            for resource in resources
            for result in resource.get("Results") or []
        )
        return findings_from_trivy_results(located_results)
