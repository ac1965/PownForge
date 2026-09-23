from __future__ import annotations

import io
from pathlib import Path
from xml.sax.saxutils import escape

from pownforge.core.models import AttackSession, Finding, FindingStatus, RunRecord, Severity
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
