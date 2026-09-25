from __future__ import annotations

from typing import Any, Iterable

# Preferred order among trivy's `CVSS` sources (a dict keyed by source name,
# e.g. "nvd"/"redhat"/"ghsa") when picking one representative score --
# confirmed against a real `trivy image` scan (CVE-2021-36159 on
# alpine:3.10 carries both "nvd" and "redhat" entries with different
# scores). "nvd" first since it's the canonical, source-agnostic scoring
# body; anything else trivy reports is still usable, just lower priority.
_TRIVY_CVSS_SOURCE_PRIORITY = ("nvd", "redhat", "ghsa")


def _cvss_from_trivy_vulnerability(vuln: dict[str, Any]) -> tuple[float, str] | None:
    """Pick one (score, vector) pair from trivy's `CVSS` field (real shape:
    `{"nvd": {"V2Score": .., "V3Score": .., "V2Vector": .., "V3Vector": ..},
    "redhat": {...}, ...}`) -- prefers a v3 score/vector over v2 (more
    precise), and _TRIVY_CVSS_SOURCE_PRIORITY's first matching source.
    Returns None when the vulnerability carries no CVSS data at all (most
    non-CVE findings, and some CVEs trivy hasn't scored)."""
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, dict) or not cvss:
        return None
    sources = list(_TRIVY_CVSS_SOURCE_PRIORITY) + [s for s in cvss if s not in _TRIVY_CVSS_SOURCE_PRIORITY]
    for source in sources:
        entry = cvss.get(source)
        if not isinstance(entry, dict):
            continue
        score = entry.get("V3Score", entry.get("V2Score"))
        vector = entry.get("V3Vector", entry.get("V2Vector"))
        if isinstance(score, (int, float)) and vector:
            return float(score), str(vector)
    return None


def findings_from_trivy_results(
    located_results: Iterable[tuple[str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Extract pownforge "_findings" dicts from trivy Result objects.

    Shared between KubernetesPlugin (`trivy k8s`) and ContainerPlugin
    (`trivy image`): both produce the same Result shape (optional
    Misconfigurations/Vulnerabilities/Secrets lists), just nested
    differently at the top level of trivy's JSON output. `location` is a
    caller-supplied string identifying where a result came from (a k8s
    resource path, or an image scan target), embedded in each finding's
    detail so results from different resources/layers aren't ambiguous.
    """
    findings: list[dict[str, Any]] = []
    for location, result in located_results:
        for m in result.get("Misconfigurations") or []:
            findings.append(
                {
                    "title": f"[{m.get('ID', '?')}] {m.get('Title') or 'misconfiguration'}",
                    # trivy uses UPPERCASE severities (HIGH, MEDIUM, ...);
                    # our Finding.severity enum is lowercase. coerce_finding()
                    # falls back to "info" for anything that still doesn't
                    # match (e.g. trivy's "UNKNOWN").
                    "severity": (m.get("Severity") or "info").lower(),
                    "detail": f"{location}: {m.get('Message') or m.get('Description') or ''}",
                }
            )
        for v in result.get("Vulnerabilities") or []:
            finding: dict[str, Any] = {
                "title": f"[{v.get('VulnerabilityID', '?')}] "
                f"{v.get('Title') or v.get('PkgName') or 'vulnerability'}",
                "severity": (v.get("Severity") or "info").lower(),
                "detail": f"{location}: {v.get('Description') or ''}",
            }
            if native_severity := v.get("Severity"):
                finding["native_severity"] = native_severity
            if cvss := _cvss_from_trivy_vulnerability(v):
                finding["cvss_score"], finding["cvss_vector"] = cvss
            findings.append(finding)
        for s in result.get("Secrets") or []:
            findings.append(
                {
                    "title": f"[{s.get('RuleID', '?')}] {s.get('Title') or 'exposed secret'}",
                    "severity": (s.get("Severity") or "info").lower(),
                    "detail": f"{location}: {s.get('Match') or ''}",
                }
            )
    return findings
