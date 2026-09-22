from __future__ import annotations

from typing import Any, Iterable


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
            findings.append(
                {
                    "title": f"[{v.get('VulnerabilityID', '?')}] "
                    f"{v.get('Title') or v.get('PkgName') or 'vulnerability'}",
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
