from __future__ import annotations

from pownforge.core.models import RunRecord, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def render(record: RunRecord) -> str:
    lines = [
        f"# Run {record.run_id}",
        "",
        f"- **Target:** {record.target}",
        f"- **Plugin:** {record.plugin}",
        f"- **Created:** {record.created_at.isoformat()}",
        f"- **Return code:** {record.evidence.returncode}",
        f"- **Command:** `{' '.join(record.evidence.command)}`",
        f"- **stdout sha256:** `{record.evidence.stdout_sha256}`",
        f"- **stderr sha256:** `{record.evidence.stderr_sha256}`",
        "",
        "## Findings",
        "",
    ]
    if record.findings:
        ordered = sorted(record.findings, key=lambda f: _SEVERITY_ORDER[f.severity])
        for finding in ordered:
            tag = "AI推定・要確認" if finding.source == "ai" else "manual"
            lines.append(
                f"- **[{finding.severity.value}]** ({tag}) {finding.title} — {finding.detail}"
            )
    else:
        lines.append("_No findings recorded yet._")

    lines += ["", "## AI分析", ""]
    if record.analysis:
        lines.append(record.analysis)
    else:
        lines.append("_`pownforge analyze` を実行すると、ここに分析草案が表示されます。_")

    lines += ["", "## Raw output", "", "```", str(record.output.get("raw_stdout", "")), "```"]
    return "\n".join(lines)
