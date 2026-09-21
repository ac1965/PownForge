from __future__ import annotations

from pownforge.core.models import RunRecord


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
        for finding in record.findings:
            lines.append(f"- **[{finding.severity}]** {finding.title} — {finding.detail}")
    else:
        lines.append(
            "_No findings recorded yet. Run `pownforge analyze` for an AI-assisted draft._"
        )
    lines += ["", "## Raw output", "", "```", str(record.output.get("raw_stdout", "")), "```"]
    return "\n".join(lines)
