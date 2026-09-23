from __future__ import annotations

import io
from pathlib import Path
from xml.sax.saxutils import escape

from pownforge.core.models import (
    AttackSession,
    Finding,
    FindingStatus,
    PreconditionStatus,
    PrimitiveRunRecord,
    RunRecord,
    Severity,
)
from pownforge.reporting.summary import summarize

# Imported lazily-at-module-level rather than inside render(): this module
# is only imported at all when PDF output is requested (see cli.py/routers),
# so importing reportlab here doesn't force the dependency on callers who
# never touch PDF. `pip install -e '.[pdf]'` installs it; render() raises a
# clear ImportError-derived message otherwise (caught in cli.py/routers).
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
except ImportError as exc:  # pragma: no cover - exercised via the "not installed" path
    raise ImportError(
        "PDF report generation needs the 'pdf' extra: pip install -e '.[pdf]' (reportlab)"
    ) from exc

# reportlab's built-in CID fonts (e.g. HeiseiKakuGo-W5) ship no glyph data
# of their own -- they render Japanese only via the PDF *viewer's* own CJK
# font substitution, and several common viewers don't have one configured,
# silently dropping every Japanese character. Embedding an actual font
# (Noto Sans JP, OFL-licensed, see fonts/OFL.txt) avoids that: the glyphs
# travel inside the PDF itself, so it renders identically everywhere.
_FONT_NAME = "NotoSansJP"
_FONT_PATH = Path(__file__).parent / "fonts" / "NotoSansJP-Regular.ttf"
if _FONT_NAME not in pdfmetrics.getRegisteredFontNames():
    pdfmetrics.registerFont(TTFont(_FONT_NAME, str(_FONT_PATH)))

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

# Same palette as reporting/html.py's .severity-* badges, so PDF/HTML/Web UI
# reports read consistently.
_SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#c0392b"),
    Severity.HIGH: colors.HexColor("#e67e22"),
    Severity.MEDIUM: colors.HexColor("#b8960c"),  # darkened from #f1c40f for contrast on white
    Severity.LOW: colors.HexColor("#3498db"),
    Severity.INFO: colors.HexColor("#7f8c8d"),
}

# Cap how much raw tool output goes into the PDF -- unlike Markdown/HTML
# (which a browser/pager can handle at any size), a multi-megabyte
# Preformatted flowable can make reportlab's layout pass pathologically
# slow. The full, unmasked output is always still in EvidenceStore/the
# Markdown/HTML reports; this is a PDF-specific readability cap, not a
# retention decision.
_MAX_RAW_OUTPUT_CHARS = 20_000


def _stylesheet():
    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle("Title", parent=base["Title"], fontName=_FONT_NAME),
        "Heading2": ParagraphStyle("Heading2", parent=base["Heading2"], fontName=_FONT_NAME, spaceBefore=10),
        "Heading3": ParagraphStyle("Heading3", parent=base["Heading3"], fontName=_FONT_NAME, spaceBefore=6),
        "Normal": ParagraphStyle("Normal", parent=base["Normal"], fontName=_FONT_NAME, leading=14),
        "Code": ParagraphStyle(
            "Code", parent=base["Code"], fontName="Courier", fontSize=8, leading=10, wordWrap="CJK"
        ),
    }
    return styles


def _kv_table(rows: list[tuple[str, str]], styles: dict) -> Table:
    data = [[Paragraph(escape(k), styles["Normal"]), Paragraph(escape(v), styles["Normal"])] for k, v in rows]
    table = Table(data, colWidths=[35 * mm, 130 * mm])
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), _FONT_NAME),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _render_finding(finding: Finding, styles: dict) -> Paragraph:
    tag = _SOURCE_LABELS.get(finding.source, "manual")
    color = _SEVERITY_COLORS[finding.severity].hexval()
    text = (
        f'<font color="{color}"><b>[{escape(finding.severity.value)}]</b></font> '
        f"({escape(tag)}, <font face=\"Courier\">{escape(finding.finding_id)}</font>) "
        f"<b>{escape(finding.title)}</b> — {escape(finding.detail)}"
    )
    return Paragraph(text, styles["Normal"])


def render(record: RunRecord) -> bytes:
    """Render RECORD as a PDF, returned as bytes (never written to disk by
    this function -- callers decide where it goes, same as html.render()/
    markdown.render()). Content mirrors those two renderers section for
    section, so the three formats stay in sync."""
    styles = _stylesheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        title=f"Run {record.run_id} — PownForge report",
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    story: list = [Paragraph(f"Run {escape(record.run_id)}", styles["Title"]), Spacer(1, 4 * mm)]

    story.append(
        _kv_table(
            [
                ("Target", record.target),
                ("Plugin", record.plugin),
                ("Created", record.created_at.isoformat()),
                ("Return code", str(record.evidence.returncode)),
                ("Command", " ".join(record.evidence.command)),
                ("Tool version", record.evidence.tool_version or "(unknown)"),
                ("stdout sha256", record.evidence.stdout_sha256),
                ("stderr sha256", record.evidence.stderr_sha256),
            ],
            styles,
        )
    )

    story.append(Paragraph("エグゼクティブサマリー", styles["Heading2"]))
    summary = summarize(record.findings)
    breakdown = (
        " / ".join(f"{sev.value} {count}" for sev, count in summary.confirmed_by_severity)
        if summary.confirmed_by_severity
        else "0"
    )
    story.append(
        _kv_table(
            [
                ("総件数", str(summary.total)),
                ("確認済み", breakdown),
                ("要確認(未検証)", str(summary.needs_review)),
                ("誤検知として却下", str(summary.false_positive)),
                ("総合評価", summary.headline),
            ],
            styles,
        )
    )

    story.append(Paragraph("Findings", styles["Heading2"]))
    if record.findings:
        for status, heading in _STATUS_SECTIONS:
            findings = sorted(
                (f for f in record.findings if f.status == status),
                key=lambda f: _SEVERITY_ORDER[f.severity],
            )
            if not findings:
                continue
            story.append(Paragraph(heading, styles["Heading3"]))
            for finding in findings:
                story.append(_render_finding(finding, styles))
                story.append(Spacer(1, 1.5 * mm))
    else:
        story.append(Paragraph("No findings recorded yet.", styles["Normal"]))

    story.append(Paragraph("AI分析", styles["Heading2"]))
    if record.analysis:
        story.append(Paragraph(escape(record.analysis), styles["Normal"]))
    else:
        story.append(
            Paragraph(
                "`pownforge analyze` を実行すると、ここに分析草案が表示されます。", styles["Normal"]
            )
        )

    if record.artifacts:
        story.append(Paragraph("Artifacts", styles["Heading2"]))
        for art in record.artifacts:
            story.append(
                Paragraph(
                    f"<b>{escape(art.description)}</b> — "
                    f'<font face="Courier">{escape(art.path or "")}</font> '
                    f"(sha256 {escape(art.sha256 or '')})",
                    styles["Normal"],
                )
            )

    story.append(Paragraph("Raw output", styles["Heading2"]))
    raw = str(record.output.get("raw_stdout", ""))
    if len(raw) > _MAX_RAW_OUTPUT_CHARS:
        raw = raw[:_MAX_RAW_OUTPUT_CHARS] + f"\n... (truncated, {len(raw)} chars total -- see the run's stored evidence for the full output)"
    story.append(Preformatted(raw or "(empty)", styles["Code"]))

    doc.build(story)
    return buf.getvalue()


def _sorted_findings(record: RunRecord, status: FindingStatus) -> list[Finding]:
    return sorted(
        (f for f in record.findings if f.status == status),
        key=lambda f: _SEVERITY_ORDER[f.severity],
    )


def render_attack_session(session: AttackSession, records: list[RunRecord]) -> bytes:
    """Render SESSION as a PDF. RECORDS must be the resolved RunRecord for
    each of `session.stages`, in the same order -- mirrors
    reporting/attack_session.py's render_markdown()/render_html() section
    for section (the Kubernetes attack-chain dashboard those two render as
    an HTML table is left out here: it doesn't have a PDF-appropriate
    layout yet, and the per-stage Findings below still carry the same
    information)."""
    styles = _stylesheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        title=f"Attack Session: {session.name} — PownForge report",
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    story: list = [Paragraph(f"Attack Session: {escape(session.name)}", styles["Title"])]
    if session.description:
        story.append(Paragraph(escape(session.description), styles["Normal"]))
    story.append(Spacer(1, 4 * mm))

    header_rows = []
    if session.engagement:
        header_rows.append(("Engagement", session.engagement))
    header_rows.append(("Stages", str(len(session.stages))))
    story.append(_kv_table(header_rows, styles))

    story.append(Paragraph("経路", styles["Heading2"]))
    if not session.stages:
        story.append(Paragraph("ステージがまだありません。", styles["Normal"]))
    for i, (stage, record) in enumerate(zip(session.stages, records), start=1):
        phase = f" [{escape(record.kill_chain_phase.value)}]" if record.kill_chain_phase else ""
        label = f" — {escape(stage.label)}" if stage.label else ""
        story.append(
            Paragraph(
                f"{i}. <b>{escape(record.target)}</b> / "
                f'<font face="Courier">{escape(record.plugin)}</font>{phase}{label} '
                f'(<font face="Courier">{escape(record.run_id)}</font>)',
                styles["Normal"],
            )
        )

    for i, (stage, record) in enumerate(zip(session.stages, records), start=1):
        story.append(Paragraph(f"Stage {i}: {escape(record.target)} / {escape(record.plugin)}", styles["Heading2"]))
        if stage.label:
            story.append(Paragraph(f"<i>{escape(stage.label)}</i>", styles["Normal"]))

        stage_rows = [
            ("Run id", record.run_id),
            ("Created", record.created_at.isoformat()),
            ("Return code", str(record.evidence.returncode)),
            ("Command", " ".join(record.evidence.command)),
        ]
        if record.kill_chain_phase:
            stage_rows.append(("Kill chain phase", record.kill_chain_phase.value))
        if record.via_target:
            stage_rows.append(("Reached via", f"{record.via_target} (engagement: {record.engagement})"))
        story.append(_kv_table(stage_rows, styles))

        if record.findings:
            for status, heading in _STATUS_SECTIONS:
                findings = _sorted_findings(record, status)
                if not findings:
                    continue
                story.append(Paragraph(heading, styles["Heading3"]))
                for finding in findings:
                    story.append(_render_finding(finding, styles))
                    story.append(Spacer(1, 1.5 * mm))
        else:
            story.append(Paragraph("No findings recorded for this stage.", styles["Normal"]))

    doc.build(story)
    return buf.getvalue()


_PRECONDITION_LABEL = {
    PreconditionStatus.MET: "met",
    PreconditionStatus.UNMET: "unmet",
    PreconditionStatus.UNKNOWN: "unknown",
}

_PRECONDITION_COLOR = {
    PreconditionStatus.MET: colors.HexColor("#1e7d34"),
    PreconditionStatus.UNMET: colors.HexColor("#c0392b"),
    PreconditionStatus.UNKNOWN: colors.HexColor("#b8960c"),
}


def render_primitive(record: PrimitiveRunRecord) -> bytes:
    """Render a PrimitiveRunRecord as a PDF (bytes). Mirrors
    reporting/primitive.py's Markdown/HTML section for section."""
    styles = _stylesheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        title=f"Primitive run {record.run_id} — PownForge report",
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    story: list = [
        Paragraph(f"Primitive run {escape(record.run_id)}", styles["Title"]),
        Spacer(1, 4 * mm),
    ]
    header = [
        ("Primitive", record.primitive),
        ("Category", record.category or "(none)"),
        ("Target", record.target),
        ("Created", record.created_at.isoformat()),
        ("Requested level", record.requested_level.value),
        ("Level reached", record.level_reached.value),
    ]
    if record.notes:
        header.append(("Note", record.notes))
    story.append(_kv_table(header, styles))

    story.append(Paragraph("前提条件 (Preconditions)", styles["Heading2"]))
    if record.preconditions.preconditions:
        for p in record.preconditions.preconditions:
            color = _PRECONDITION_COLOR[p.status].hexval()
            detail = f" — {escape(p.detail)}" if p.detail else ""
            story.append(
                Paragraph(
                    f'<font color="{color}"><b>{_PRECONDITION_LABEL[p.status]}</b></font> '
                    f'<font face="Courier">{escape(p.id)}</font>: {escape(p.description)}{detail}',
                    styles["Normal"],
                )
            )
    else:
        story.append(Paragraph("前提条件は評価されていません。", styles["Normal"]))

    evidence = record.evidence
    story.append(Paragraph("観測 (Observations — 事実)", styles["Heading2"]))
    if evidence and evidence.observations:
        for o in evidence.observations:
            story.append(
                Paragraph(
                    f'<font face="Courier">{escape(o.type)}</font> '
                    f"({escape(o.provenance.kind.value)}): {escape(o.detail)}",
                    styles["Normal"],
                )
            )
    else:
        story.append(Paragraph("観測はありません。", styles["Normal"]))

    if evidence and evidence.artifacts:
        story.append(Paragraph("保存された証拠 (Artifacts)", styles["Heading2"]))
        for a in evidence.artifacts:
            loc = f" {escape(a.path)}" if a.path else ""
            story.append(Paragraph(f"<b>{escape(a.type)}</b>{loc}: {escape(a.description)}", styles["Normal"]))

    story.append(Paragraph("Findings (観測から導いた診断)", styles["Heading2"]))
    if evidence and evidence.findings:
        for finding in evidence.findings:
            story.append(_render_finding(finding, styles))
            story.append(Spacer(1, 1.5 * mm))
    else:
        story.append(Paragraph("Findingはありません。", styles["Normal"]))

    story.append(Paragraph("Claims (上位の主張 — 推論)", styles["Heading2"]))
    if evidence and evidence.claims:
        for c in evidence.claims:
            support = f" (根拠: {escape(', '.join(c.supported_by))})" if c.supported_by else ""
            story.append(
                Paragraph(f"<b>[{escape(c.confidence.value)}]</b> {escape(c.statement)}{support}", styles["Normal"])
            )
    else:
        story.append(Paragraph("Claimはありません。", styles["Normal"]))

    story.append(Paragraph("生成リソースとクリーンアップ (Resources & Cleanup)", styles["Heading2"]))
    if record.resources:
        for r in record.resources:
            story.append(
                Paragraph(
                    f'<font face="Courier">{escape(r.status.value)}</font> '
                    f"<b>{escape(r.type)}</b>: {escape(r.description)}",
                    styles["Normal"],
                )
            )
    else:
        story.append(Paragraph("生成されたリソースはありません。", styles["Normal"]))
    if record.residual_resources:
        story.append(
            Paragraph(
                f'<font color="#c0392b"><b>⚠ {len(record.residual_resources)} '
                "件のリソースがクリーンアップ未検証のまま残っています。</b></font>",
                styles["Normal"],
            )
        )

    doc.build(story)
    return buf.getvalue()


def render_engagement(report: "EngagementReport") -> bytes:
    """Render a cross-cutting EngagementReport (RunRecord + PrimitiveRunRecord)
    as a PDF. Mirrors reporting/engagement.py's Markdown/HTML sections."""
    from pownforge.core.models import ConfidenceLevel

    styles = _stylesheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        title=f"Engagement report — {report.scope_label}",
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    story: list = [
        Paragraph(f"Engagement report — {escape(report.scope_label)}", styles["Title"]),
        Spacer(1, 4 * mm),
    ]

    all_findings = [f for r in report.runs for f in r.findings]
    summary = summarize(all_findings)
    breakdown = (
        " / ".join(f"{sev.value} {count}" for sev, count in summary.confirmed_by_severity)
        if summary.confirmed_by_severity
        else "0"
    )
    confirmed_claims = [
        (p, c)
        for p in report.primitive_runs
        if p.evidence
        for c in p.evidence.claims
        if c.confidence == ConfidenceLevel.CONFIRMED
    ]
    residual = [p for p in report.primitive_runs if p.residual_resources]

    story.append(
        _kv_table(
            [
                ("Targets", ", ".join(report.targets()) or "(none)"),
                ("Scan/manual runs", str(len(report.runs))),
                ("Primitive runs", str(len(report.primitive_runs))),
                ("確認済み指摘", breakdown),
                ("要確認指摘", str(summary.needs_review)),
                ("確認済みの主張", str(len(confirmed_claims))),
                ("残留があるrun", str(len(residual))),
            ],
            styles,
        )
    )

    story.append(Paragraph("タイムライン", styles["Heading2"]))
    timeline = sorted(
        [("scan", r.created_at, r) for r in report.runs]
        + [("primitive", p.created_at, p) for p in report.primitive_runs],
        key=lambda e: e[1],
    )
    for kind, when, record in timeline:
        if kind == "scan":
            text = (
                f'<font face="Courier">{escape(when.isoformat())}</font> <b>scan</b> '
                f"{escape(record.target)} / {escape(record.plugin)} "
                f"(findings {len(record.findings)})"
            )
        else:
            n_claims = len(record.evidence.claims) if record.evidence else 0
            tag = " (residual)" if record.residual_resources else ""
            text = (
                f'<font face="Courier">{escape(when.isoformat())}</font> <b>primitive</b> '
                f"{escape(record.target)} / {escape(record.primitive)} "
                f"(reached {escape(record.level_reached.value)}, claims {n_claims}){tag}"
            )
        story.append(Paragraph(text, styles["Normal"]))

    story.append(Paragraph("確認済みの指摘・主張", styles["Heading2"]))
    confirmed_findings = [f for f in all_findings if f.status == FindingStatus.CONFIRMED]
    if not confirmed_findings and not confirmed_claims:
        story.append(Paragraph("確認済みの指摘・主張はまだありません。", styles["Normal"]))
    for finding in confirmed_findings:
        story.append(_render_finding(finding, styles))
        story.append(Spacer(1, 1.5 * mm))
    for prim, claim in confirmed_claims:
        story.append(
            Paragraph(
                f"<b>[confirmed]</b> (primitive claim, {escape(prim.primitive)}) {escape(claim.statement)}",
                styles["Normal"],
            )
        )

    if residual:
        story.append(Paragraph("クリーンアップ未検証の残留リソース", styles["Heading2"]))
        for prim in residual:
            for r in prim.residual_resources:
                story.append(
                    Paragraph(
                        f'<font color="#c0392b">{escape(prim.run_id)} {escape(r.type)} '
                        f"({escape(r.status.value)}): {escape(r.description)}</font>",
                        styles["Normal"],
                    )
                )

    doc.build(story)
    return buf.getvalue()
