"""Markdown/HTML renderers for a PrimitiveRunRecord. Mirrors the final
Finding shape from docs/handbook.md §15: what was tested, why it was testable
(preconditions), what was actually observed (evidence, 4 layers, observed vs
inferred), what changed and whether it was cleaned. The PDF renderer lives in
reporting/pdf.py (render_primitive), kept together with the other PDF code."""

from __future__ import annotations

import html as html_escape

from pownforge.core.models import Finding, PreconditionStatus, PrimitiveRunRecord

_PRECONDITION_LABEL = {
    PreconditionStatus.MET: "✓ met",
    PreconditionStatus.UNMET: "✗ unmet",
    PreconditionStatus.UNKNOWN: "? unknown",
}

_SOURCE_LABELS = {"ai": "AI推定", "tool": "ツール検出", "manual": "manual"}


def _finding_md(finding: Finding) -> str:
    tag = _SOURCE_LABELS.get(finding.source, finding.source)
    return f"- **[{finding.severity.value}]** ({tag}, `{finding.finding_id}`) {finding.title} — {finding.detail}"


def render_markdown(record: PrimitiveRunRecord) -> str:
    lines = [
        f"# Primitive run {record.run_id}",
        "",
        f"- **Primitive:** {record.primitive}",
        f"- **Category:** {record.category or '_(none)_'}",
        f"- **Target:** {record.target}",
        f"- **Created:** {record.created_at.isoformat()}",
        f"- **Requested level:** {record.requested_level.value}",
        f"- **Level reached:** {record.level_reached.value}",
    ]
    if record.notes:
        lines.append(f"- **Note:** {record.notes}")

    lines += ["", "## 前提条件 (Preconditions)", ""]
    if record.preconditions.preconditions:
        for p in record.preconditions.preconditions:
            detail = f" — {p.detail}" if p.detail else ""
            lines.append(f"- **{_PRECONDITION_LABEL[p.status]}** `{p.id}`: {p.description}{detail}")
    else:
        lines.append("_前提条件は評価されていません。_")

    evidence = record.evidence
    lines += ["", "## 観測 (Observations — 事実)", ""]
    if evidence and evidence.observations:
        for o in evidence.observations:
            lines.append(
                f"- `{o.type}` ({o.provenance.kind.value}, {o.timestamp.isoformat()}): {o.detail}"
            )
    else:
        lines.append("_観測はありません。_")

    if evidence and evidence.artifacts:
        lines += ["", "## 保存された証拠 (Artifacts)", ""]
        for a in evidence.artifacts:
            loc = f" `{a.path}`" if a.path else ""
            sha = f" (sha256 `{a.sha256}`)" if a.sha256 else ""
            lines.append(f"- **{a.type}**{loc}{sha}: {a.description}")

    lines += ["", "## Findings (観測から導いた診断)", ""]
    if evidence and evidence.findings:
        lines += [_finding_md(f) for f in evidence.findings]
    else:
        lines.append("_Findingはありません。_")

    lines += ["", "## Claims (上位の主張 — 推論)", ""]
    if evidence and evidence.claims:
        for c in evidence.claims:
            support = f" (根拠: {', '.join(c.supported_by)})" if c.supported_by else ""
            lines.append(f"- **[{c.confidence.value}]** {c.statement}{support}")
    else:
        lines.append("_Claimはありません。_")

    lines += ["", "## 生成リソースとクリーンアップ (Resources & Cleanup)", ""]
    if record.resources:
        for r in record.resources:
            lines.append(f"- `{r.status.value}` **{r.type}**: {r.description}")
    else:
        lines.append("_生成されたリソースはありません。_")
    if record.residual_resources:
        lines += [
            "",
            f"> ⚠ **{len(record.residual_resources)} 件のリソースがクリーンアップ未検証のまま残っています。**",
        ]
    return "\n".join(lines)


# Same palette/structure as reporting/html.py so the reports read consistently.
_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
dl { display: grid; grid-template-columns: 11rem 1fr; gap: .25rem .75rem; margin: 0; }
dt { font-weight: bold; }
dd { margin: 0; word-break: break-word; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
ul { padding-left: 1.2rem; }
.met { color: #1e7d34; font-weight: bold; }
.unmet { color: #c0392b; font-weight: bold; }
.unknown { color: #b8960c; font-weight: bold; }
.badge { display: inline-block; font-size: .75rem; font-weight: bold; padding: .1rem .4rem;
         border-radius: 4px; margin-right: .4rem; text-transform: uppercase; color: white; }
.severity-critical .badge { background: #c0392b; }
.severity-high .badge { background: #e67e22; }
.severity-medium .badge { background: #f1c40f; color: black; }
.severity-low .badge { background: #3498db; }
.severity-info .badge { background: #95a5a6; }
.residual { background: #fdecea; border: 1px solid #c0392b; padding: .5rem .75rem; border-radius: 4px; }
"""

_STATUS_CLASS = {
    PreconditionStatus.MET: "met",
    PreconditionStatus.UNMET: "unmet",
    PreconditionStatus.UNKNOWN: "unknown",
}


def _esc(value: object) -> str:
    return html_escape.escape(str(value))


def render_html(record: PrimitiveRunRecord) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="ja">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Primitive run {_esc(record.run_id)} — PownForge report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>Primitive run {_esc(record.run_id)}</h1>",
        "<dl>",
        f"<dt>Primitive</dt><dd>{_esc(record.primitive)}</dd>",
        f"<dt>Category</dt><dd>{_esc(record.category or '(none)')}</dd>",
        f"<dt>Target</dt><dd>{_esc(record.target)}</dd>",
        f"<dt>Created</dt><dd>{_esc(record.created_at.isoformat())}</dd>",
        f"<dt>Requested level</dt><dd>{_esc(record.requested_level.value)}</dd>",
        f"<dt>Level reached</dt><dd>{_esc(record.level_reached.value)}</dd>",
    ]
    if record.notes:
        parts.append(f"<dt>Note</dt><dd>{_esc(record.notes)}</dd>")
    parts += ["</dl>", "<h2>前提条件 (Preconditions)</h2>"]

    if record.preconditions.preconditions:
        parts.append("<ul>")
        for p in record.preconditions.preconditions:
            detail = f" — {_esc(p.detail)}" if p.detail else ""
            parts.append(
                f'<li><span class="{_STATUS_CLASS[p.status]}">{_esc(_PRECONDITION_LABEL[p.status])}</span> '
                f"<code>{_esc(p.id)}</code>: {_esc(p.description)}{detail}</li>"
            )
        parts.append("</ul>")
    else:
        parts.append("<p><em>前提条件は評価されていません。</em></p>")

    evidence = record.evidence
    parts.append("<h2>観測 (Observations — 事実)</h2>")
    if evidence and evidence.observations:
        parts.append("<ul>")
        for o in evidence.observations:
            parts.append(
                f"<li><code>{_esc(o.type)}</code> ({_esc(o.provenance.kind.value)}, "
                f"{_esc(o.timestamp.isoformat())}): {_esc(o.detail)}</li>"
            )
        parts.append("</ul>")
    else:
        parts.append("<p><em>観測はありません。</em></p>")

    if evidence and evidence.artifacts:
        parts.append("<h2>保存された証拠 (Artifacts)</h2><ul>")
        for a in evidence.artifacts:
            loc = f" <code>{_esc(a.path)}</code>" if a.path else ""
            sha = f" (sha256 <code>{_esc(a.sha256)}</code>)" if a.sha256 else ""
            parts.append(f"<li><strong>{_esc(a.type)}</strong>{loc}{sha}: {_esc(a.description)}</li>")
        parts.append("</ul>")

    parts.append("<h2>Findings (観測から導いた診断)</h2>")
    if evidence and evidence.findings:
        for f in evidence.findings:
            tag = _SOURCE_LABELS.get(f.source, f.source)
            parts.append(
                f'<div class="finding severity-{f.severity.value}">'
                f'<span class="badge">{_esc(f.severity.value)}</span>'
                f"({_esc(tag)}, <code>{_esc(f.finding_id)}</code>) "
                f"<strong>{_esc(f.title)}</strong> — {_esc(f.detail)}</div>"
            )
    else:
        parts.append("<p><em>Findingはありません。</em></p>")

    parts.append("<h2>Claims (上位の主張 — 推論)</h2>")
    if evidence and evidence.claims:
        parts.append("<ul>")
        for c in evidence.claims:
            support = f" (根拠: {_esc(', '.join(c.supported_by))})" if c.supported_by else ""
            parts.append(
                f"<li><strong>[{_esc(c.confidence.value)}]</strong> {_esc(c.statement)}{support}</li>"
            )
        parts.append("</ul>")
    else:
        parts.append("<p><em>Claimはありません。</em></p>")

    parts.append("<h2>生成リソースとクリーンアップ (Resources &amp; Cleanup)</h2>")
    if record.resources:
        parts.append("<ul>")
        for r in record.resources:
            parts.append(
                f"<li><code>{_esc(r.status.value)}</code> <strong>{_esc(r.type)}</strong>: "
                f"{_esc(r.description)}</li>"
            )
        parts.append("</ul>")
    else:
        parts.append("<p><em>生成されたリソースはありません。</em></p>")
    if record.residual_resources:
        parts.append(
            f'<p class="residual">⚠ {len(record.residual_resources)} '
            "件のリソースがクリーンアップ未検証のまま残っています。</p>"
        )

    parts += ["</body>", "</html>"]
    return "\n".join(parts)
