from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pownforge.core.models import Target, TargetKind
from pownforge.plugins._trivy import findings_from_trivy_results
from pownforge.plugins.base import Plugin, PluginError


class KubernetesPlugin(Plugin):
    name = "kubernetes"
    version = "0.1.0"
    description = "Cluster misconfiguration, RBAC, and workload vulnerability scanning via trivy k8s."
    required_tool = "trivy"
    expected_kind = TargetKind.HOST
    kind_hint = "address should be a kubeconfig context name, e.g. kind-pownforge-lab."

    def __init__(self) -> None:
        self._json_path: Path | None = None

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["trivy", "--version"]

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

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
