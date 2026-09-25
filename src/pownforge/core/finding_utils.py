from __future__ import annotations

from typing import Any

from pownforge.core.models import Finding, Severity


def coerce_finding(item: dict[str, Any], source: str) -> Finding | None:
    """Build a Finding from a loosely-typed dict (LLM output, a plugin's own
    tool-native matches, etc.), defensively.

    Skips entries with no title (nothing to show). Falls back severity to
    INFO when the value isn't one of our known levels, rather than dropping
    the whole finding just because the source's severity label didn't match —
    the title/detail are still worth keeping, just without trusting the
    unverified severity claim.
    """
    title = item.get("title")
    if not title:
        return None
    detail = str(item.get("detail", ""))
    raw_technique_ids = item.get("attack_technique_ids", [])
    technique_ids = [str(t) for t in raw_technique_ids] if isinstance(raw_technique_ids, list) else []

    raw_cvss_score = item.get("cvss_score")
    cvss_score = float(raw_cvss_score) if isinstance(raw_cvss_score, (int, float)) else None
    raw_cvss_vector = item.get("cvss_vector")
    cvss_vector = str(raw_cvss_vector) if raw_cvss_vector else None
    raw_native_severity = item.get("native_severity")
    native_severity = str(raw_native_severity) if raw_native_severity else None

    common_fields = dict(
        title=str(title),
        detail=detail,
        source=source,
        attack_technique_ids=technique_ids,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        native_severity=native_severity,
    )
    try:
        return Finding(severity=item.get("severity", "info"), **common_fields)
    except ValueError:
        return Finding(severity=Severity.INFO, **common_fields)
