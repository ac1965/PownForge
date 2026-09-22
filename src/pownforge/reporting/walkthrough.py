from __future__ import annotations

import html as html_escape

from pownforge.core.models import Finding, FindingStatus, RunRecord, Severity
from pownforge.core.walkthrough import Walkthrough
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

_NARRATIVE_NOTICE = (
    "以下はAIが生成した草稿です。個々のfindingの検証状態は各runの詳細セクションを"
    "参照してください。"
)

_SUGGESTIONS_NOTICE = "これらはAIによる提案です。実行するかどうかは人間が判断してください。"


def _targets(records: list[RunRecord]) -> list[str]:
    seen: list[str] = []
    for record in records:
        if record.target not in seen:
            seen.append(record.target)
    return seen


def _sorted_findings(record: RunRecord, status: FindingStatus) -> list[Finding]:
    return sorted(
        (f for f in record.findings if f.status == status),
        key=lambda f: _SEVERITY_ORDER[f.severity],
    )


def _all_findings(records: list[RunRecord]) -> list[Finding]:
    return [finding for record in records for finding in record.findings]


def render_markdown(walkthrough: Walkthrough) -> str:
    records = walkthrough.records
    lines = [
        f"# Walkthrough: {', '.join(_targets(records))} ({len(records)} runs)",
        "",
        f"- **Runs:** {len(records)}",
        f"- **Period:** {records[0].created_at.isoformat()} — {records[-1].created_at.isoformat()}",
        "",
        "## エグゼクティブサマリー",
        "",
    ]
    summary = summarize(_all_findings(records))
    lines.append(f"- **総件数:** {summary.total} ({len(records)} runs)")
    if summary.confirmed_by_severity:
        breakdown = " / ".join(f"{sev.value} {count}" for sev, count in summary.confirmed_by_severity)
        lines.append(f"- **確認済み:** {breakdown}")
    else:
        lines.append("- **確認済み:** 0")
    lines.append(f"- **要確認(未検証):** {summary.needs_review}")
    lines.append(f"- **誤検知として却下:** {summary.false_positive}")
    lines.append(f"- **総合評価:** {summary.headline}")

    lines += [
        "",
        "## ナラティブ(AI生成・要確認)",
        "",
        f"_{_NARRATIVE_NOTICE}_",
        "",
        walkthrough.narrative,
        "",
        "## AIの提案(要確認)",
        "",
        f"_{_SUGGESTIONS_NOTICE}_",
        "",
    ]
    if walkthrough.suggestions:
        for suggestion in walkthrough.suggestions:
            plugin_note = f" (`plugin: {suggestion.plugin}`)" if suggestion.plugin else ""
            lines.append(f"- **{suggestion.title}**{plugin_note} — {suggestion.rationale}")
    else:
        lines.append("_具体的な提案はありませんでした。_")

    for i, record in enumerate(records, start=1):
        lines += [
            "",
            f"## Run {i}: {record.target} / {record.plugin}",
            "",
            f"- **Run id:** {record.run_id}",
            f"- **Created:** {record.created_at.isoformat()}",
            f"- **Return code:** {record.evidence.returncode}",
            f"- **Command:** `{' '.join(record.evidence.command)}`",
            f"- **Tool version:** {record.evidence.tool_version or '_unknown_'}",
        ]
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
            lines += ["", "_No findings recorded for this run._"]

    return "\n".join(lines)


_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
h3 { font-size: 1rem; }
.narrative { background: #f9f7f0; border-left: 3px solid #d9c98a; padding: .75rem 1rem; }
.suggestion { background: #eef5fb; border-left: 3px solid #4a90d9; padding: .5rem .75rem;
              margin: 0 0 .5rem 0; }
.suggestion .plugin-badge { display: inline-block; font-size: .7rem; font-family: ui-monospace,
              SFMono-Regular, Menlo, monospace; background: #dce8f5; color: #1a4971;
              padding: .05rem .35rem; border-radius: 3px; margin-left: .4rem; }
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
"""


def _esc(value: object) -> str:
    return html_escape.escape(str(value))


def render_html(walkthrough: Walkthrough) -> str:
    records = walkthrough.records
    parts = [
        "<!doctype html>",
        '<html lang="ja">',
        "<head>",
        '<meta charset="utf-8">',
        "<title>Walkthrough — PownForge report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>Walkthrough: {_esc(', '.join(_targets(records)))} ({len(records)} runs)</h1>",
        "<dl>",
        f"<dt>Runs</dt><dd>{len(records)}</dd>",
        "<dt>Period</dt>"
        f"<dd>{_esc(records[0].created_at.isoformat())} — {_esc(records[-1].created_at.isoformat())}</dd>",
        "</dl>",
        "<h2>エグゼクティブサマリー</h2>",
    ]
    summary = summarize(_all_findings(records))
    if summary.confirmed_by_severity:
        breakdown = " / ".join(f"{_esc(sev.value)} {count}" for sev, count in summary.confirmed_by_severity)
    else:
        breakdown = "0"
    parts += [
        "<dl>",
        f"<dt>総件数</dt><dd>{summary.total} ({len(records)} runs)</dd>",
        f"<dt>確認済み</dt><dd>{breakdown}</dd>",
        f"<dt>要確認(未検証)</dt><dd>{summary.needs_review}</dd>",
        f"<dt>誤検知として却下</dt><dd>{summary.false_positive}</dd>",
        f"<dt>総合評価</dt><dd>{_esc(summary.headline)}</dd>",
        "</dl>",
        "<h2>ナラティブ(AI生成・要確認)</h2>",
        f"<p><em>{_esc(_NARRATIVE_NOTICE)}</em></p>",
        f'<div class="narrative">{_esc(walkthrough.narrative)}</div>',
        "<h2>AIの提案(要確認)</h2>",
        f"<p><em>{_esc(_SUGGESTIONS_NOTICE)}</em></p>",
    ]
    if walkthrough.suggestions:
        for suggestion in walkthrough.suggestions:
            plugin_badge = (
                f'<span class="plugin-badge">{_esc(suggestion.plugin)}</span>'
                if suggestion.plugin
                else ""
            )
            parts.append(
                f'<div class="suggestion"><strong>{_esc(suggestion.title)}</strong>{plugin_badge}'
                f" — {_esc(suggestion.rationale)}</div>"
            )
    else:
        parts.append("<p><em>具体的な提案はありませんでした。</em></p>")

    for i, record in enumerate(records, start=1):
        parts += [
            f"<h2>Run {i}: {_esc(record.target)} / {_esc(record.plugin)}</h2>",
            "<dl>",
            f"<dt>Run id</dt><dd>{_esc(record.run_id)}</dd>",
            f"<dt>Created</dt><dd>{_esc(record.created_at.isoformat())}</dd>",
            f"<dt>Return code</dt><dd>{_esc(record.evidence.returncode)}</dd>",
            f"<dt>Command</dt><dd>{_esc(' '.join(record.evidence.command))}</dd>",
            f"<dt>Tool version</dt><dd>{_esc(record.evidence.tool_version or '(unknown)')}</dd>",
        ]
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
            parts.append("<p><em>No findings recorded for this run.</em></p>")

    parts += ["</body>", "</html>"]
    return "\n".join(parts)
