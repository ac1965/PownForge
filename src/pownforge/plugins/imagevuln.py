from __future__ import annotations

import json
import shlex
import shutil
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# grype's own severity vocabulary (Title Case). Anything else it might ever
# emit falls back to "info" via .get() below, same fallback coerce_finding()
# (core/finding_utils.py) already applies to an unmapped value.
_SEVERITY_BY_GRYPE_SEVERITY = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "info",
    "Unknown": "info",
}


def _cvss_from_grype_vulnerability(vuln: dict[str, Any]) -> tuple[float, str] | None:
    """Pick one (score, vector) pair from grype's `vulnerability.cvss` list
    -- confirmed via a real `grype alpine:3.10` scan to be a list of
    entries from possibly multiple sources/CVSS versions for the same
    vulnerability (e.g. NVD's own v3.1 *and* v2.0 scores, plus a second
    "Secondary" source's v3.1 score). Prefers a "Primary"-typed entry, and
    among those the highest CVSS version -- same rationale as trivy's nvd
    preference in _trivy.py: pick the most authoritative, most precise
    score rather than averaging or listing every one."""
    entries = vuln.get("cvss")
    if not isinstance(entries, list) or not entries:
        return None

    def sort_key(entry: dict[str, Any]) -> tuple[bool, tuple[int, ...]]:
        is_primary = entry.get("type") == "Primary"
        version = str(entry.get("version") or "0")
        try:
            version_tuple = tuple(int(part) for part in version.split("."))
        except ValueError:
            version_tuple = (0,)
        return (is_primary, version_tuple)

    candidates = [e for e in entries if isinstance(e, dict)]
    if not candidates:
        return None
    best = max(candidates, key=sort_key)
    score = (best.get("metrics") or {}).get("baseScore")
    vector = best.get("vector")
    if isinstance(score, (int, float)) and vector:
        return float(score), str(vector)
    return None


class ImagevulnPlugin(Plugin):
    name = "imagevuln"
    version = "0.1.0"
    description = (
        "Container image vulnerability scanning via grype -- a second, independently-maintained "
        "vulnerability DB from the `container` plugin's trivy, to catch what one DB misses."
    )
    required_tool = "grype"
    expected_kind = TargetKind.HOST
    kind_hint = "address should be an image reference, e.g. nginx:1.25 (same convention as the container plugin)."

    options_schema = (
        PluginOption(
            name="only-fixed",
            description="grype --only-fixed: report only vulnerabilities that have a known fix.",
            default="false",
            choices=["true", "false"],
        ),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["grype", "version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        db_status_path = execution.path("db-status.json")
        report_path = execution.path("grype.json")

        # GRYPE_DB_AUTO_UPDATE=false: a scan never implicitly downloads a
        # new DB (§5.2 -- DB updates are an explicit, separate `grype db
        # update` run by the operator/image build, never hidden inside an
        # ordinary scan). GRYPE_CHECK_FOR_APP_UPDATE=false: grype
        # otherwise checks for a newer release over the network on every
        # invocation, which -- like semgrep's equivalent check (see
        # plugins/sast.py) -- doesn't fail fast on an --internal lab
        # network, it hangs until the OS connect timeout.
        env_prefix = "GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false"
        scan_args = ["grype", shlex.quote(target.address), "-o", "json"]
        if str(options.get("only-fixed", "false")).lower() in ("true", "1"):
            scan_args.append("--only-fixed")
        # `db status` first so a stale/missing DB is recorded even if the
        # scan itself then fails outright (missing DB -> grype errors out).
        # `;` not `&&`: still want the (failed) scan's own error captured
        # rather than silently skipped.
        script = (
            f"{env_prefix} grype db status -o json > {shlex.quote(str(db_status_path))}; "
            f"{env_prefix} {' '.join(scan_args)} > {shlex.quote(str(report_path))}"
        )
        return ["sh", "-c", script]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        db_status_path = execution.path("db-status.json")
        report_path = execution.path("grype.json")

        db_built_at = None
        if db_status_path.exists():
            db_built_at = self._parse_db_built_at(db_status_path)

        matches: list[dict[str, Any]] = []
        if report_path.exists():
            matches = self._parse_report(report_path)

        return {
            "target": target.address,
            "tool": "grype",
            "db_built_at": db_built_at,
            "matches": matches,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [self._finding_from_match(match) for match in matches],
        }

    @staticmethod
    def _finding_from_match(match: dict[str, Any]) -> dict[str, Any]:
        finding: dict[str, Any] = {
            "title": f"{match['id']} in {match['package']}@{match['version']}",
            "severity": _SEVERITY_BY_GRYPE_SEVERITY.get(match["severity"], "info"),
            "detail": (
                f"grype (independent DB from `container`/trivy): {match['id']} affects "
                f"{match['package']}@{match['version']}"
                + (f", fixed in {match['fixed_in']}" if match["fixed_in"] else " (no fix available)")
            ),
            "native_severity": match["severity"],
        }
        if cvss := match.get("cvss"):
            finding["cvss_score"], finding["cvss_vector"] = cvss
        return finding

    @staticmethod
    def _parse_db_built_at(db_status_path) -> str | None:
        try:
            data = json.loads(db_status_path.read_text())
        except json.JSONDecodeError:
            return None
        built = data.get("built")
        return built if isinstance(built, str) else None

    @staticmethod
    def _parse_report(report_path) -> list[dict[str, Any]]:
        try:
            data = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return []
        raw_matches = data.get("matches")
        if not isinstance(raw_matches, list):
            return []

        seen: set[tuple[str, str, str]] = set()
        matches: list[dict[str, Any]] = []
        for raw in raw_matches:
            if not isinstance(raw, dict):
                continue
            vuln = raw.get("vulnerability") or {}
            artifact = raw.get("artifact") or {}
            vuln_id = vuln.get("id", "")
            package = artifact.get("name", "")
            version = artifact.get("version", "")
            key = (vuln_id, package, version)
            if key in seen:
                continue
            seen.add(key)
            fix = vuln.get("fix") or {}
            fix_versions = fix.get("versions") or []
            matches.append(
                {
                    "id": vuln_id,
                    "severity": vuln.get("severity", "Unknown"),
                    "package": package,
                    "version": version,
                    "type": artifact.get("type"),
                    "fixed_in": fix_versions[0] if fix_versions else None,
                    "cvss": _cvss_from_grype_vulnerability(vuln),
                }
            )
        return matches
