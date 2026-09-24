from __future__ import annotations

import json
import shutil
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins._source_path import resolve_registered_directory
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# checkov only populates a per-check `severity` when authenticated against
# Bridgecrew/Prisma Cloud (--bc-api-key), which this plugin never sets
# (§3.6/§6.2: no cloud upload, offline only) -- so `severity` is always None
# here, not just sometimes. A failed check is a real misconfiguration with
# unknown-without-cloud-lookup severity, not nothing: "medium" is the
# documented fixed fallback (see docs/handbook.md §6), analogous to
# `secrets`' fixed "high" for the same "tool doesn't report one" reason.
_SEVERITY = "medium"

_DEFAULT_FRAMEWORKS = "kubernetes,terraform,dockerfile"


class IacPlugin(Plugin):
    name = "iac"
    version = "0.1.0"
    description = "Static analysis of not-yet-applied Kubernetes/Terraform/Dockerfile configuration via checkov."
    required_tool = "checkov"
    expected_kind = TargetKind.PATH
    kind_hint = "register the manifest/IaC directory with --kind path (same as secrets/sast)."

    options_schema = (
        PluginOption(
            name="framework",
            description="Comma-separated checkov --framework values to scan.",
            default=_DEFAULT_FRAMEWORKS,
        ),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["checkov", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        root = resolve_registered_directory(self.name, target.address)

        # checkov's --output-file-path is a DIRECTORY it writes
        # results_json.json into (confirmed against checkov 3.3.10 -- not
        # documented in --help), not a file path itself.
        report_dir = execution.path("checkov-output")
        frameworks = [f.strip() for f in str(options.get("framework", _DEFAULT_FRAMEWORKS)).split(",") if f.strip()]

        return [
            "checkov",
            "--directory",
            str(root),
            "--framework",
            *frameworks,
            "--output",
            "json",
            "--output-file-path",
            str(report_dir),
            "--compact",
            # Offline, read-only, no cloud account required or used:
            "--skip-download",  # never fetch policies/doc links/severities from Prisma Cloud
            "--skip-results-upload",  # never upload results (moot without --bc-api-key, but explicit)
            # Autofix/write-back is never requested -- checkov's own CLI has
            # no such flag to begin with (it's a diagnosis-only tool), so
            # this plugin's read-only guarantee holds by the tool's own
            # design, not just by omission.
        ]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        report_path = execution.path("checkov-output") / "results_json.json"
        failures: list[dict[str, Any]] = []
        summary: dict[str, Any] = {}
        if report_path.exists():
            failures, summary = self._parse_report(report_path)

        return {
            "target": target.address,
            "tool": "checkov",
            "summary": summary,
            "failures": failures,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [
                {
                    "title": f"{failure['check_id']}: {failure['check_name']}",
                    "severity": _SEVERITY,
                    "detail": f"{failure['resource']} ({failure['file_path']})",
                }
                for failure in failures
            ],
        }

    @staticmethod
    def _parse_report(report_path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        try:
            raw = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return [], {}

        # checkov emits one report object per --framework when more than one
        # framework matched files, or a single object when only one did.
        reports = raw if isinstance(raw, list) else [raw]

        seen: set[tuple[str, str, str]] = set()
        failures: list[dict[str, Any]] = []
        totals = {"passed": 0, "failed": 0, "skipped": 0}
        for report in reports:
            if not isinstance(report, dict):
                continue
            summary = report.get("summary") or {}
            for key in totals:
                totals[key] += summary.get(key, 0) or 0
            for check in report.get("results", {}).get("failed_checks", []) or []:
                check_id = check.get("check_id", "")
                resource = check.get("resource", "")
                file_path = check.get("file_path", "")
                key = (check_id, resource, file_path)
                if key in seen:
                    continue
                seen.add(key)
                failures.append(
                    {
                        "check_id": check_id,
                        "check_name": check.get("check_name", check_id),
                        "resource": resource,
                        "file_path": file_path,
                    }
                )
        return failures, totals
