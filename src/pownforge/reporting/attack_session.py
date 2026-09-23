from __future__ import annotations

import html as html_escape

from pownforge.core.models import AttackSession, Finding, FindingStatus, RunRecord, Severity
from pownforge.reporting import kubernetes_dashboard

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


def _sorted_findings(record: RunRecord, status: FindingStatus) -> list[Finding]:
    return sorted(
        (f for f in record.findings if f.status == status),
        key=lambda f: _SEVERITY_ORDER[f.severity],
    )


def render_markdown(session: AttackSession, records: list[RunRecord]) -> str:
    """Render SESSION as Markdown. RECORDS must be the resolved RunRecord
    for each of `session.stages`, in the same order -- this function never
    loads anything itself (no EvidenceStore dependency), matching
    reporting/walkthrough.py's split between data loading (core/) and
    rendering (reporting/). Purely a read-only view: it never executes
    anything and asserts nothing beyond what each run's own Findings
    already record."""
    lines = [f"# Attack Session: {session.name}", ""]
    if session.description:
        lines.append(session.description)
        lines.append("")
    if session.engagement:
        lines.append(f"- **Engagement:** `{session.engagement}`")
    lines.append(f"- **Stages:** {len(session.stages)}")
    lines.append("")

    lines.append("## 経路")
    lines.append("")
    if not session.stages:
        lines.append("_ステージがまだありません。_")
    for i, (stage, record) in enumerate(zip(session.stages, records), start=1):
        phase = f" [{record.kill_chain_phase.value}]" if record.kill_chain_phase else ""
        label = f" — {stage.label}" if stage.label else ""
        lines.append(f"{i}. **{record.target}** / `{record.plugin}`{phase}{label} (`{record.run_id}`)")
    lines.append("")

    for i, (stage, record) in enumerate(zip(session.stages, records), start=1):
        lines += [
            f"## Stage {i}: {record.target} / {record.plugin}",
            "",
        ]
        if stage.label:
            lines.append(f"_{stage.label}_")
            lines.append("")
        lines += [
            f"- **Run id:** {record.run_id}",
            f"- **Created:** {record.created_at.isoformat()}",
            f"- **Return code:** {record.evidence.returncode}",
            f"- **Command:** `{' '.join(record.evidence.command)}`",
        ]
        if record.kill_chain_phase:
            lines.append(f"- **Kill chain phase:** {record.kill_chain_phase.value}")
        if record.via_target:
            lines.append(f"- **Reached via:** `{record.via_target}` (engagement: `{record.engagement}`)")
        lines += ["", "### Findings"]
        if record.findings:
            for status, heading in _STATUS_SECTIONS:
                findings = _sorted_findings(record, status)
                if not findings:
                    continue
                lines += ["", f"#### {heading}", ""]
                for finding in findings:
                    tag = _SOURCE_LABELS.get(finding.source, "manual")
                    lines.append(
                        f"- **[{finding.severity.value}]** ({tag}, `{finding.finding_id}`) "
                        f"{finding.title} — {finding.detail}"
                    )
        else:
            lines += ["", "_No findings recorded for this stage._"]
        lines.append("")

    return "\n".join(lines)


_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
h3 { font-size: 1rem; }
ol.path li { margin-bottom: .3rem; }
dl { display: grid; grid-template-columns: 9rem 1fr; gap: .25rem .75rem; margin: 0; }
dt { font-weight: bold; }
dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
.finding { margin: 0 0 .75rem 0; }
.badge { display: inline-block; font-size: .75rem; font-weight: bold; padding: .1rem .4rem;
         border-radius: 4px; margin-right: .4rem; text-transform: uppercase; color: white; }
.severity-critical .badge { background: #c0392b; }
.severity-high .badge { background: #e67e22; }
.severity-medium .badge { background: #f1c40f; color: black; }
.severity-low .badge { background: #3498db; }
.severity-info .badge { background: #95a5a6; }
.source { font-size: .75rem; opacity: .7; margin-right: .4rem; }
.stage-label { font-style: italic; color: #555; }
""" + kubernetes_dashboard.EXTRA_STYLE


def _esc(value: object) -> str:
    return html_escape.escape(str(value))


def render_html(session: AttackSession, records: list[RunRecord]) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="ja">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Attack Session: {_esc(session.name)} — PownForge report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>Attack Session: {_esc(session.name)}</h1>",
    ]
    if session.description:
        parts.append(f"<p>{_esc(session.description)}</p>")
    parts.append("<dl>")
    if session.engagement:
        parts.append(f"<dt>Engagement</dt><dd>{_esc(session.engagement)}</dd>")
    parts.append(f"<dt>Stages</dt><dd>{len(session.stages)}</dd>")
    parts.append("</dl>")

    parts.append("<h2>経路</h2>")
    if not session.stages:
        parts.append("<p><em>ステージがまだありません。</em></p>")
    else:
        parts.append("<ol class='path'>")
        for stage, record in zip(session.stages, records):
            phase = f" [{_esc(record.kill_chain_phase.value)}]" if record.kill_chain_phase else ""
            label = f' <span class="stage-label">— {_esc(stage.label)}</span>' if stage.label else ""
            parts.append(
                f"<li><strong>{_esc(record.target)}</strong> / <code>{_esc(record.plugin)}</code>"
                f"{phase}{label} (<code>{_esc(record.run_id)}</code>)</li>"
            )
        parts.append("</ol>")

    dashboard = kubernetes_dashboard.render_section(records)
    if dashboard:
        parts.append(dashboard)

    for i, (stage, record) in enumerate(zip(session.stages, records), start=1):
        parts.append(f"<h2>Stage {i}: {_esc(record.target)} / {_esc(record.plugin)}</h2>")
        if stage.label:
            parts.append(f'<p class="stage-label">{_esc(stage.label)}</p>')
        parts += [
            "<dl>",
            f"<dt>Run id</dt><dd>{_esc(record.run_id)}</dd>",
            f"<dt>Created</dt><dd>{_esc(record.created_at.isoformat())}</dd>",
            f"<dt>Return code</dt><dd>{_esc(record.evidence.returncode)}</dd>",
            f"<dt>Command</dt><dd>{_esc(' '.join(record.evidence.command))}</dd>",
        ]
        if record.kill_chain_phase:
            parts.append(f"<dt>Kill chain phase</dt><dd>{_esc(record.kill_chain_phase.value)}</dd>")
        if record.via_target:
            parts.append(
                f"<dt>Reached via</dt><dd>{_esc(record.via_target)} (engagement: {_esc(record.engagement)})</dd>"
            )
        parts.append("</dl>")

        if record.findings:
            for status, heading in _STATUS_SECTIONS:
                findings = _sorted_findings(record, status)
                if not findings:
                    continue
                parts.append(f"<h3>{_esc(heading)}</h3>")
                for finding in findings:
                    tag = _SOURCE_LABELS.get(finding.source, "manual")
                    parts.append(
                        f'<div class="finding severity-{finding.severity.value}">'
                        f'<span class="badge">{_esc(finding.severity.value)}</span>'
                        f'<span class="source">({_esc(tag)}, <code>{_esc(finding.finding_id)}</code>)</span>'
                        f"<strong>{_esc(finding.title)}</strong> — {_esc(finding.detail)}"
                        f"</div>"
                    )
        else:
            parts.append("<p><em>No findings recorded for this stage.</em></p>")

    parts += ["</body>", "</html>"]
    return "\n".join(parts)
