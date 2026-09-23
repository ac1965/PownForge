from __future__ import annotations

from pownforge.core.models import Finding, FindingStatus, RunRecord, Severity
from pownforge.reporting.summary import summarize

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_STATUS_SECTIONS = [
    (FindingStatus.CONFIRMED, "確認済み"),
    (FindingStatus.NEEDS_REVIEW, "要確認"),
    (FindingStatus.FALSE_POSITIVE, "誤検知として却下"),
]

_SOURCE_LABELS = {"ai": "AI推定", "tool": "ツール検出"}


def _render_finding(finding: Finding) -> str:
    tag = _SOURCE_LABELS.get(finding.source, "manual")
    return (
        f"- **[{finding.severity.value}]** ({tag}, `{finding.finding_id}`) "
        f"{finding.title} — {finding.detail}"
    )


def render(record: RunRecord) -> str:
    lines = [
        f"# Run {record.run_id}",
        "",
        f"- **Target:** {record.target}",
        f"- **Plugin:** {record.plugin}",
        f"- **Created:** {record.created_at.isoformat()}",
        f"- **Return code:** {record.evidence.returncode}",
        f"- **Command:** `{' '.join(record.evidence.command)}`",
        f"- **Tool version:** {record.evidence.tool_version or '_unknown_'}",
        f"- **stdout sha256:** `{record.evidence.stdout_sha256}`",
        f"- **stderr sha256:** `{record.evidence.stderr_sha256}`",
        "",
        "## エグゼクティブサマリー",
        "",
    ]
    summary = summarize(record.findings)
    lines.append(f"- **総件数:** {summary.total}")
    if summary.confirmed_by_severity:
        breakdown = " / ".join(f"{sev.value} {count}" for sev, count in summary.confirmed_by_severity)
        lines.append(f"- **確認済み:** {breakdown}")
    else:
        lines.append("- **確認済み:** 0")
    lines.append(f"- **要確認(未検証):** {summary.needs_review}")
    lines.append(f"- **誤検知として却下:** {summary.false_positive}")
    lines.append(f"- **総合評価:** {summary.headline}")

    lines += ["", "## Findings"]
    if record.findings:
        for status, heading in _STATUS_SECTIONS:
            findings = sorted(
                (f for f in record.findings if f.status == status),
                key=lambda f: _SEVERITY_ORDER[f.severity],
            )
            if not findings:
                continue
            lines += ["", f"### {heading}", ""]
            lines += [_render_finding(f) for f in findings]
    else:
        lines += ["", "_No findings recorded yet._"]

    lines += ["", "## AI分析", ""]
    if record.analysis:
        lines.append(record.analysis)
    else:
        lines.append("_`pownforge analyze` を実行すると、ここに分析草案が表示されます。_")

    if record.artifacts:
        lines += ["", "## Artifacts", ""]
        for art in record.artifacts:
            lines.append(f"- **{art.description}** — `{art.path}` (sha256 `{art.sha256}`)")

    lines += ["", "## Raw output", "", "```", str(record.output.get("raw_stdout", "")), "```"]
    return "\n".join(lines)
