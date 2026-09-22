from __future__ import annotations

from pownforge.core.models import Finding, FindingStatus, RunRecord, Severity

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


def _render_finding(finding: Finding) -> str:
    tag = "AI推定" if finding.source == "ai" else "manual"
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
        "## Findings",
    ]
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

    lines += ["", "## Raw output", "", "```", str(record.output.get("raw_stdout", "")), "```"]
    return "\n".join(lines)
