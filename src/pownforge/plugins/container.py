from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins._trivy import findings_from_trivy_results
from pownforge.plugins.base import Plugin, PluginError, PluginExecution


class ContainerPlugin(Plugin):
    name = "container"
    version = "0.1.0"
    description = "Container image vulnerability, misconfiguration, and secret scanning via trivy image."
    required_tool = "trivy"
    expected_kind = TargetKind.HOST
    kind_hint = "address should be an image reference, e.g. nginx:1.25."

    options_schema = (
        PluginOption(name="severity", description="trivy --severity, e.g. CRITICAL,HIGH."),
        PluginOption(name="ignore-unfixed", description="true to pass --ignore-unfixed.", choices=["true", "false", "1", "0"]),
        PluginOption(name="scanners", description="trivy --scanners, e.g. vuln,secret."),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["trivy", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        json_path = execution.path("trivy-image.json")

        # target.address holds an image reference (e.g. "nginx:1.25" or
        # "registry.example.com/app:latest"), not a host/URL — trivy
        # resolves and inspects it directly (pulling it if not already
        # present locally).
        args = [
            "trivy",
            "image",
            target.address,
            "-f",
            "json",
            "-o",
            str(json_path),
            "--no-progress",
        ]
        if severity := options.get("severity"):
            args += ["--severity", str(severity)]
        if str(options.get("ignore-unfixed", "")).lower() in ("true", "1"):
            args.append("--ignore-unfixed")
        if scanners := options.get("scanners"):
            args += ["--scanners", str(scanners)]
        return args

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        json_path = execution.path("trivy-image.json")
        if json_path.exists():
            results = self._parse_json(json_path)

        located_results = ((result.get("Target") or target.address, result) for result in results)
        return {
            "target": target.address,
            "tool": "trivy",
            "results": results,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": findings_from_trivy_results(located_results),
        }

    @staticmethod
    def _parse_json(json_path: Path) -> list[dict[str, Any]]:
        try:
            data = json.loads(json_path.read_text())
        except json.JSONDecodeError:
            return []
        return data.get("Results") or []
