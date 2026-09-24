from __future__ import annotations

import importlib.resources
import json
import shutil
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins._source_path import resolve_registered_directory
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# semgrep's own severities. INFO is intentionally left out of the default
# mapping's happy path -- anything semgrep reports that isn't ERROR/WARNING
# falls through to "info" via .get()'s default, same fallback
# coerce_finding() (core/finding_utils.py) already applies to an unmapped
# value, so nothing is silently dropped.
_SEVERITY_BY_SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info",
}

_DEFAULT_RULES_RESOURCE = "python.yaml"

# A caller-supplied --option rules=<value> must be a local file or directory
# that already exists -- never a registry shortcut/URL, which would
# reintroduce the network fetch + registry login this plugin exists to
# avoid (semgrep's own `--config auto`/`--config p/...`/`--config r/...`
# behavior). Checked before the value ever reaches the command line.
_FORBIDDEN_RULES_PREFIXES = ("auto", "p/", "r/", "http://", "https://")


class SastPlugin(Plugin):
    name = "sast"
    version = "0.1.0"
    description = "Static analysis for known-vulnerable code patterns via semgrep, using a fixed local ruleset."
    required_tool = "semgrep"
    expected_kind = TargetKind.PATH
    kind_hint = "register the source directory with --kind path."

    options_schema = (
        PluginOption(
            name="rules",
            description=(
                "Local YAML rule file or directory to use instead of the bundled default "
                "(never a registry shortcut/URL -- see plugins/sast.py)."
            ),
        ),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["semgrep", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        root = resolve_registered_directory(self.name, target.address)

        rules = self._resolve_rules(options.get("rules"))
        report_path = execution.path("semgrep.json")

        return [
            "semgrep",
            "scan",
            "--config",
            str(rules),
            "--json",
            "--json-output",
            str(report_path),
            # No telemetry regardless of where --config came from.
            "--metrics=off",
            # Read-only diagnosis: never let semgrep rewrite the scanned
            # files, even though only a fixed local ruleset (never
            # --config auto) is ever used here.
            "--no-autofix",
            str(root),
        ]

    def _resolve_rules(self, raw: Any) -> Path:
        if not raw:
            return importlib.resources.files("pownforge.plugins._sast_rules").joinpath(_DEFAULT_RULES_RESOURCE)
        rules = str(raw)
        lowered = rules.lower()
        if any(lowered == p or lowered.startswith(p) for p in _FORBIDDEN_RULES_PREFIXES):
            raise PluginError(
                f"sast plugin: --option rules={rules!r} looks like a Semgrep Registry reference or URL, "
                "which this plugin refuses (it would fetch rules over the network); pass a local file or "
                "directory path instead"
            )
        path = Path(rules)
        if not path.exists():
            raise PluginError(f"sast plugin: --option rules path '{rules}' does not exist")
        return path

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        report_path = execution.path("semgrep.json")
        matches: list[dict[str, Any]] = []
        if report_path.exists():
            matches = self._parse_report(report_path)

        return {
            "target": target.address,
            "tool": "semgrep",
            "matches": matches,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [
                {
                    "title": f"{match['check_id']}",
                    "severity": _SEVERITY_BY_SEMGREP_SEVERITY.get(match["severity"], "info"),
                    "detail": f"{match['message']} ({match['path']}:{match['line']})",
                }
                for match in matches
            ],
        }

    @staticmethod
    def _parse_report(report_path: Path) -> list[dict[str, Any]]:
        try:
            data = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return []
        results = data.get("results")
        if not isinstance(results, list):
            return []

        seen: set[tuple[str, str, int]] = set()
        matches: list[dict[str, Any]] = []
        for raw in results:
            if not isinstance(raw, dict):
                continue
            check_id = raw.get("check_id", "")
            path = raw.get("path", "")
            line = (raw.get("start") or {}).get("line", 0)
            key = (check_id, path, line)
            if key in seen:
                continue
            seen.add(key)
            extra = raw.get("extra") or {}
            matches.append(
                {
                    "check_id": check_id,
                    "path": path,
                    "line": line,
                    "end_line": (raw.get("end") or {}).get("line", line),
                    "severity": extra.get("severity", "INFO"),
                    "message": extra.get("message", check_id),
                }
            )
        return matches
