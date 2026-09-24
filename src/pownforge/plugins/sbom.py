from __future__ import annotations

import json
import shutil
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution


class SbomPlugin(Plugin):
    name = "sbom"
    version = "0.1.0"
    description = "Software Bill of Materials (package inventory) for a container image via syft."
    required_tool = "syft"
    expected_kind = TargetKind.HOST
    kind_hint = "address should be an image reference, e.g. nginx:1.25 (same convention as the container plugin)."

    options_schema = (
        PluginOption(
            name="scope",
            description="syft --scope: which image layers to catalog.",
            default="squashed",
            choices=["squashed", "all-layers", "deep-squashed"],
        ),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["syft", "version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        sbom_path = execution.path("sbom.cdx.json")
        scope = str(options.get("scope", "squashed"))

        # No --enrich: syft's package-data enrichment fetches additional
        # metadata from online sources (golang/java/javascript/python/vcpkg
        # registries), which this plugin never opts into (§3.6: no traffic
        # beyond the diagnosed target).
        return [
            "syft",
            "scan",
            target.address,
            "--scope",
            scope,
            "--output",
            f"cyclonedx-json={sbom_path}",
            "--quiet",
        ]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        sbom_path = execution.path("sbom.cdx.json")
        components: list[dict[str, Any]] = []
        if sbom_path.exists():
            components = self._parse_sbom(sbom_path)

        by_type: dict[str, int] = {}
        for component in components:
            by_type[component["type"]] = by_type.get(component["type"], 0) + 1

        return {
            "target": target.address,
            "tool": "syft",
            "format": "cyclonedx-json",
            # The SBOM itself is not a vulnerability, so this plugin never
            # sets "_findings" -- it's an inventory, persisted as ordinary
            # Evidence (RunRecord.output, atomic write) like every other
            # plugin's normalized result. `imagevuln` (grype) is the
            # companion plugin that turns package/version data into
            # findings.
            "package_count": len(components),
            "packages_by_type": by_type,
            "components": components,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }

    @staticmethod
    def _parse_sbom(sbom_path) -> list[dict[str, Any]]:
        try:
            data = json.loads(sbom_path.read_text())
        except json.JSONDecodeError:
            return []
        raw_components = data.get("components")
        if not isinstance(raw_components, list):
            return []
        components: list[dict[str, Any]] = []
        for raw in raw_components:
            if not isinstance(raw, dict):
                continue
            components.append(
                {
                    "name": raw.get("name"),
                    "version": raw.get("version"),
                    "type": raw.get("type", "unknown"),
                    "purl": raw.get("purl"),
                }
            )
        return components
