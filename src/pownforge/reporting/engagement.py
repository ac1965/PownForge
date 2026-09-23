"""Markdown/HTML renderers for a cross-cutting EngagementReport (RunRecord +
PrimitiveRunRecord). PDF lives in reporting/pdf.py (render_engagement)."""

from __future__ import annotations

import html as html_escape
from datetime import datetime
from typing import Literal

from pownforge.core.engagement_report import EngagementReport
from pownforge.core.models import ConfidenceLevel, PrimitiveRunRecord, RunRecord
from pownforge.reporting.summary import summarize

TimelineEntry = tuple[Literal["scan", "primitive"], datetime, object]


def _timeline(report: EngagementReport) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = [("scan", r.created_at, r) for r in report.runs]
    entries += [("primitive", p.created_at, p) for p in report.primitive_runs]
    return sorted(entries, key=lambda e: e[1])


def _all_findings(report: EngagementReport):
    return [f for r in report.runs for f in r.findings]


def _confirmed_claims(report: EngagementReport) -> list[tuple[PrimitiveRunRecord, object]]:
    out = []
    for p in report.primitive_runs:
        if p.evidence:
            for claim in p.evidence.claims:
                if claim.confidence == ConfidenceLevel.CONFIRMED:
                    out.append((p, claim))
    return out


def _residual(report: EngagementReport) -> list[PrimitiveRunRecord]:
    return [p for p in report.primitive_runs if p.residual_resources]


def render_markdown(report: EngagementReport) -> str:
    summary = summarize(_all_findings(report))
    lines = [
        f"# Engagement report — {report.scope_label}",
        "",
        f"- **Targets:** {', '.join(report.targets()) or '(none)'}",
        f"- **Scan/manual runs:** {len(report.runs)}",
        f"- **Primitive runs:** {len(report.primitive_runs)}",
        "",
        "## エグゼクティブサマリー",
        "",
        f"- **スキャン指摘 総件数:** {summary.total}",
    ]
    if summary.confirmed_by_severity:
        breakdown = " / ".join(f"{sev.value} {count}" for sev, count in summary.confirmed_by_severity)
        lines.append(f"- **確認済み指摘:** {breakdown}")
    else:
        lines.append("- **確認済み指摘:** 0")
    lines.append(f"- **要確認(未検証)指摘:** {summary.needs_review}")
    lines.append(f"- **確認済みの主張(primitive claims):** {len(_confirmed_claims(report))}")
    residual = _residual(report)
    lines.append(f"- **クリーンアップ未検証の残留があるrun:** {len(residual)}")

    lines += ["", "## タイムライン", ""]
    for kind, when, record in _timeline(report):
        if kind == "scan":
            run: RunRecord = record  # type: ignore[assignment]
            confirmed = sum(1 for f in run.findings if f.status.value == "confirmed")
            lines.append(
                f"- `{when.isoformat()}` **scan** {run.target} / `{run.plugin}` "
                f"(findings {len(run.findings)}, confirmed {confirmed}) `{run.run_id}`"
            )
        else:
            prim: PrimitiveRunRecord = record  # type: ignore[assignment]
            n_findings = len(prim.evidence.findings) if prim.evidence else 0
            n_claims = len(prim.evidence.claims) if prim.evidence else 0
            residual_tag = " ⚠残留" if prim.residual_resources else ""
            lines.append(
                f"- `{when.isoformat()}` **primitive** {prim.target} / `{prim.primitive}` "
                f"(reached {prim.level_reached.value}, findings {n_findings}, claims {n_claims}){residual_tag} "
                f"`{prim.run_id}`"
            )

    lines += ["", "## 確認済みの指摘・主張", ""]
    confirmed_findings = [f for f in _all_findings(report) if f.status.value == "confirmed"]
    claims = _confirmed_claims(report)
    if not confirmed_findings and not claims:
        lines.append("_確認済みの指摘・主張はまだありません。_")
    for f in confirmed_findings:
        lines.append(f"- **[{f.severity.value}]** (scan finding, `{f.finding_id}`) {f.title} — {f.detail}")
    for prim, claim in claims:
        lines.append(f"- **[confirmed]** (primitive claim, `{prim.primitive}`) {claim.statement}")

    if residual:
        lines += ["", "## クリーンアップ未検証の残留リソース", ""]
        for prim in residual:
            for r in prim.residual_resources:
                lines.append(f"- `{prim.run_id}` {r.type} ({r.status.value}): {r.description}")

    return "\n".join(lines)


_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
ul { padding-left: 1.2rem; }
.scan { color: #2c3e50; }
.primitive { color: #16607a; }
.badge { display: inline-block; font-size: .7rem; font-weight: bold; padding: .05rem .35rem;
         border-radius: 4px; margin-right: .3rem; text-transform: uppercase; }
.badge.scan { background: #ecf0f1; }
.badge.primitive { background: #d6eaf1; }
.residual { background: #fdecea; border: 1px solid #c0392b; padding: .5rem .75rem; border-radius: 4px; }
"""


def _esc(value: object) -> str:
    return html_escape.escape(str(value))


def render_html(report: EngagementReport) -> str:
    summary = summarize(_all_findings(report))
    breakdown = (
        " / ".join(f"{_esc(sev.value)} {count}" for sev, count in summary.confirmed_by_severity)
        if summary.confirmed_by_severity
        else "0"
    )
    residual = _residual(report)
    claims = _confirmed_claims(report)
    parts = [
        "<!doctype html>",
        '<html lang="ja">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Engagement report — {_esc(report.scope_label)}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>Engagement report — {_esc(report.scope_label)}</h1>",
        "<dl>",
        f"<dt>Targets</dt><dd>{_esc(', '.join(report.targets()) or '(none)')}</dd>",
        f"<dt>Scan/manual runs</dt><dd>{len(report.runs)}</dd>",
        f"<dt>Primitive runs</dt><dd>{len(report.primitive_runs)}</dd>",
        "</dl>",
        "<h2>エグゼクティブサマリー</h2>",
        "<dl>",
        f"<dt>スキャン指摘 総件数</dt><dd>{summary.total}</dd>",
        f"<dt>確認済み指摘</dt><dd>{breakdown}</dd>",
        f"<dt>要確認(未検証)指摘</dt><dd>{summary.needs_review}</dd>",
        f"<dt>確認済みの主張</dt><dd>{len(claims)}</dd>",
        f"<dt>残留があるrun</dt><dd>{len(residual)}</dd>",
        "</dl>",
        "<h2>タイムライン</h2>",
        "<ul>",
    ]
    for kind, when, record in _timeline(report):
        if kind == "scan":
            run: RunRecord = record  # type: ignore[assignment]
            parts.append(
                f'<li><span class="badge scan">scan</span> <code>{_esc(when.isoformat())}</code> '
                f"{_esc(run.target)} / <code>{_esc(run.plugin)}</code> "
                f"(findings {len(run.findings)}) <code>{_esc(run.run_id)}</code></li>"
            )
        else:
            prim: PrimitiveRunRecord = record  # type: ignore[assignment]
            n_claims = len(prim.evidence.claims) if prim.evidence else 0
            tag = " ⚠" if prim.residual_resources else ""
            parts.append(
                f'<li><span class="badge primitive">primitive</span> <code>{_esc(when.isoformat())}</code> '
                f"{_esc(prim.target)} / <code>{_esc(prim.primitive)}</code> "
                f"(reached {_esc(prim.level_reached.value)}, claims {n_claims}){tag} "
                f"<code>{_esc(prim.run_id)}</code></li>"
            )
    parts.append("</ul>")

    parts.append("<h2>確認済みの指摘・主張</h2>")
    confirmed_findings = [f for f in _all_findings(report) if f.status.value == "confirmed"]
    if not confirmed_findings and not claims:
        parts.append("<p><em>確認済みの指摘・主張はまだありません。</em></p>")
    else:
        parts.append("<ul>")
        for f in confirmed_findings:
            parts.append(
                f"<li><strong>[{_esc(f.severity.value)}]</strong> (scan finding) "
                f"{_esc(f.title)} — {_esc(f.detail)}</li>"
            )
        for prim, claim in claims:
            parts.append(
                f"<li><strong>[confirmed]</strong> (primitive claim, <code>{_esc(prim.primitive)}</code>) "
                f"{_esc(claim.statement)}</li>"
            )
        parts.append("</ul>")

    if residual:
        parts.append("<h2>クリーンアップ未検証の残留リソース</h2>")
        parts.append('<div class="residual"><ul>')
        for prim in residual:
            for r in prim.residual_resources:
                parts.append(
                    f"<li><code>{_esc(prim.run_id)}</code> {_esc(r.type)} "
                    f"({_esc(r.status.value)}): {_esc(r.description)}</li>"
                )
        parts.append("</ul></div>")

    parts += ["</body>", "</html>"]
    return "\n".join(parts)
