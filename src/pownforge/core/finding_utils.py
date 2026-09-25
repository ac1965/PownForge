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
    try:
        return Finding(
            title=str(title),
            severity=item.get("severity", "info"),
            detail=detail,
            source=source,
            attack_technique_ids=technique_ids,
        )
    except ValueError:
        return Finding(
            title=str(title),
            severity=Severity.INFO,
            detail=detail,
            source=source,
            attack_technique_ids=technique_ids,
        )
