from __future__ import annotations

import json
import shutil
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins._source_path import resolve_registered_directory
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# gitleaks doesn't report a severity per finding -- every leak is "a secret
# was hardcoded somewhere it shouldn't be". A single fixed severity is the
# honest mapping (there's nothing tool-native to map from), rather than
# inventing per-rule severities gitleaks itself doesn't provide. See
# docs/handbook.md §6.
_SEVERITY = "high"

# Fields kept in the normalized output and in findings. Deliberately does
# NOT include gitleaks' own "Secret"/"Match" keys, even though --redact
# already replaces their values with the literal string "REDACTED" -- this
# plugin never stores or forwards those keys at all, so a future gitleaks
# version that redacts less aggressively (or a --redact=<n> below 100, which
# this plugin never sets) still can't leak a value through PownForge's own
# output. Only rule id, file path, line numbers, commit, and the
# tool-computed fingerprint (a hash, not the secret) are kept.
_KEPT_FIELDS = ("RuleID", "Description", "File", "StartLine", "EndLine", "Commit", "Fingerprint")


class SecretsPlugin(Plugin):
    name = "secrets"
    version = "0.1.0"
    description = "Hardcoded secret/credential detection in source code via gitleaks."
    required_tool = "gitleaks"
    expected_kind = TargetKind.PATH
    kind_hint = "register the source directory with --kind path."

    options_schema = (
        PluginOption(
            name="history",
            description="Scan git commit history too (default: working tree only).",
            default="false",
            choices=["true", "false"],
        ),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["gitleaks", "version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        root = resolve_registered_directory(self.name, target.address)

        report_path = execution.path("gitleaks.json")
        args = [
            "gitleaks",
            "detect",
            "--source",
            str(root),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            # 100% redaction (the default) of the "Secret"/"Match" fields in
            # the report itself, not just console/log output -- confirmed
            # against a real gitleaks 8.30.1 run (docs/handbook.md §6).
            "--redact",
            # A leak found is not a tool failure; keep the process exit code
            # meaning "gitleaks ran successfully" like every other plugin,
            # not "a secret was found".
            "--exit-code",
            "0",
            "--no-banner",
        ]
        # Default: working-tree files only (--no-git). Scanning git history
        # can surface secrets already removed from HEAD but still reachable
        # in past commits -- opt in explicitly since it's slower and needs
        # the target to actually be a git repository.
        if str(options.get("history", "false")).lower() not in ("true", "1"):
            args.append("--no-git")
        return args

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        report_path = execution.path("gitleaks.json")
        leaks: list[dict[str, Any]] = []
        if report_path.exists():
            leaks = self._parse_report(report_path)

        return {
            "target": target.address,
            "tool": "gitleaks",
            "leaks": leaks,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [
                {
                    "title": f"Secret detected: {leak['RuleID']}",
                    "severity": _SEVERITY,
                    "detail": (
                        f"{leak.get('Description', leak['RuleID'])} "
                        f"({leak['File']}:{leak['StartLine']}, fingerprint={leak['Fingerprint']})"
                    ),
                }
                for leak in leaks
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

        seen: set[str] = set()
        leaks: list[dict[str, Any]] = []
        for raw in data:
            if not isinstance(raw, dict):
                continue
            fingerprint = raw.get("Fingerprint", "")
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            leaks.append({field: raw.get(field) for field in _KEPT_FIELDS})
        return leaks
