from __future__ import annotations

import html as html_escape

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

# Same palette as webui/src/index.css's .severity-*.badge, so a report
# generated on the CLI looks consistent with the Web UI's Run detail page.
_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
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
pre { background: #f5f5f5; padding: 1rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
"""


def _esc(value: object) -> str:
    return html_escape.escape(str(value))


def _render_finding(finding: Finding) -> str:
    tag = _SOURCE_LABELS.get(finding.source, "manual")
    return (
        f'<div class="finding severity-{finding.severity.value}">'
        f'<span class="badge">{_esc(finding.severity.value)}</span>'
        f'<span class="source">({_esc(tag)}, <code>{_esc(finding.finding_id)}</code>)</span>'
        f"<strong>{_esc(finding.title)}</strong> — {_esc(finding.detail)}"
        f"</div>"
    )


def render(record: RunRecord) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="ja">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Run {_esc(record.run_id)} — PownForge report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>Run {_esc(record.run_id)}</h1>",
        "<dl>",
        f"<dt>Target</dt><dd>{_esc(record.target)}</dd>",
        f"<dt>Plugin</dt><dd>{_esc(record.plugin)}</dd>",
        f"<dt>Created</dt><dd>{_esc(record.created_at.isoformat())}</dd>",
        f"<dt>Return code</dt><dd>{_esc(record.evidence.returncode)}</dd>",
        f"<dt>Command</dt><dd>{_esc(' '.join(record.evidence.command))}</dd>",
        f"<dt>Tool version</dt><dd>{_esc(record.evidence.tool_version or '(unknown)')}</dd>",
        f"<dt>stdout sha256</dt><dd>{_esc(record.evidence.stdout_sha256)}</dd>",
        f"<dt>stderr sha256</dt><dd>{_esc(record.evidence.stderr_sha256)}</dd>",
        "</dl>",
        "<h2>エグゼクティブサマリー</h2>",
    ]
    summary = summarize(record.findings)
    if summary.confirmed_by_severity:
        breakdown = " / ".join(f"{_esc(sev.value)} {count}" for sev, count in summary.confirmed_by_severity)
    else:
        breakdown = "0"
    parts += [
        "<dl>",
        f"<dt>総件数</dt><dd>{summary.total}</dd>",
        f"<dt>確認済み</dt><dd>{breakdown}</dd>",
        f"<dt>要確認(未検証)</dt><dd>{summary.needs_review}</dd>",
        f"<dt>誤検知として却下</dt><dd>{summary.false_positive}</dd>",
        f"<dt>総合評価</dt><dd>{_esc(summary.headline)}</dd>",
        "</dl>",
        "<h2>Findings</h2>",
    ]

    if record.findings:
        for status, heading in _STATUS_SECTIONS:
            findings = sorted(
                (f for f in record.findings if f.status == status),
                key=lambda f: _SEVERITY_ORDER[f.severity],
            )
            if not findings:
                continue
            parts.append(f"<h3>{_esc(heading)}</h3>")
            parts += [_render_finding(f) for f in findings]
    else:
        parts.append("<p><em>No findings recorded yet.</em></p>")

    parts.append("<h2>AI分析</h2>")
    if record.analysis:
        parts.append(f"<p>{_esc(record.analysis)}</p>")
    else:
        parts.append("<p><em>`pownforge analyze` を実行すると、ここに分析草案が表示されます。</em></p>")

    if record.artifacts:
        parts.append("<h2>Artifacts</h2><ul>")
        for art in record.artifacts:
            parts.append(
                f"<li><strong>{_esc(art.description)}</strong> — <code>{_esc(art.path)}</code> "
                f"(sha256 <code>{_esc(art.sha256)}</code>)</li>"
            )
        parts.append("</ul>")

    parts += [
        "<h2>Raw output</h2>",
        f"<pre>{_esc(record.output.get('raw_stdout', ''))}</pre>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts)
