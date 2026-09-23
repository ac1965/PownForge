from __future__ import annotations

import io

import pytest

pytest.importorskip("reportlab")
pypdf = pytest.importorskip("pypdf")

from pownforge.core.models import (
    AttackSession,
    AttackSessionStage,
    Evidence,
    Finding,
    KillChainPhase,
    RunRecord,
)
from pownforge.reporting import pdf


def _record(**overrides) -> RunRecord:
    evidence_fields = {
        "command": ["nmap", "127.0.0.1"],
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "returncode": 0,
        "stdout_sha256": "abc",
        "stderr_sha256": "def",
    }
    evidence_fields.update(overrides.pop("evidence_overrides", {}))
    evidence = Evidence(**evidence_fields)
    defaults = dict(target="lab", plugin="network", evidence=evidence, output={"raw_stdout": "hi"})
    defaults.update(overrides)
    return RunRecord(**defaults)


def _text(data: bytes) -> str:
    reader = pypdf.PdfReader(io.BytesIO(data))
    return "\n".join(page.extract_text() for page in reader.pages)


def test_render_produces_a_valid_pdf() -> None:
    data = pdf.render(_record())
    assert data.startswith(b"%PDF-")
    # Parses without raising -- a corrupt/truncated PDF would fail here.
    assert len(pypdf.PdfReader(io.BytesIO(data)).pages) >= 1


def test_render_includes_run_metadata() -> None:
    text = _text(pdf.render(_record(run_id="run123", target="lab-web", plugin="nuclei")))
    assert "Run run123" in text
    assert "lab-web" in text
    assert "nuclei" in text


def test_render_renders_japanese_text_correctly() -> None:
    # Regression test: reportlab's built-in CID fonts (e.g. HeiseiKakuGo-W5)
    # render Japanese only via the PDF *viewer's* own CJK font, and several
    # common viewers silently drop every CJK glyph. This asserts the actual
    # extracted text contains Japanese section headings, not just "the PDF
    # parses" -- catches a regression to an unembedded font.
    text = _text(pdf.render(_record()))
    assert "エグゼクティブサマリー" in text
    assert "総件数" in text
    assert "確認済み" in text
    assert "要確認(未検証)" in text
    assert "AI分析" in text


def test_render_without_findings_shows_placeholder() -> None:
    text = _text(pdf.render(_record()))
    assert "No findings recorded yet." in text
    assert "pownforge analyze" in text


def test_render_with_findings_lists_severity_and_detail() -> None:
    record = _record(
        findings=[
            Finding(title="Open port 3000", severity="medium", detail="ppp?", source="ai"),
            Finding(title="Manual note", severity="low", detail="checked by hand"),
        ]
    )
    text = _text(pdf.render(record))
    assert "[medium]" in text
    assert "Open port 3000" in text
    assert "AI推定" in text
    assert "要確認" in text


def test_render_orders_findings_by_severity_desc() -> None:
    record = _record(
        findings=[
            Finding(title="low one", severity="low"),
            Finding(title="critical one", severity="critical"),
            Finding(title="info one", severity="info"),
        ]
    )
    text = _text(pdf.render(record))
    assert text.index("critical one") < text.index("low one") < text.index("info one")


def test_render_groups_findings_by_status() -> None:
    record = _record(
        findings=[
            Finding(title="confirmed one", status="confirmed"),
            Finding(title="pending one", status="needs-review"),
            Finding(title="dismissed one", status="false-positive"),
        ]
    )
    text = _text(pdf.render(record))
    assert text.index("確認済み") < text.index("confirmed one")
    assert text.index("要確認") < text.index("pending one")
    assert text.index("誤検知として却下") < text.index("dismissed one")


def test_render_with_analysis_shows_text_not_placeholder() -> None:
    record = _record(analysis="Looks like a dev server; no confirmed vulnerabilities.")
    text = _text(pdf.render(record))
    assert "Looks like a dev server; no confirmed vulnerabilities." in text
    assert "pownforge analyze" not in text


def test_render_truncates_very_long_raw_output() -> None:
    huge_output = "x" * 50_000
    record = _record(output={"raw_stdout": huge_output})
    text = _text(pdf.render(record))
    assert "truncated" in text
    assert len(text) < len(huge_output)


def test_render_does_not_crash_on_markup_like_characters() -> None:
    # reportlab's Paragraph interprets a small XML-like markup subset --
    # unescaped "<"/"&" from tool output would raise a parse error deep
    # inside reportlab (e.g. "<b>bold</b> & stuff" without escaping the
    # bare "&" breaks its parser) rather than a clean PownForge exception.
    # Unlike HTML, a PDF has no script-execution context, so the only thing
    # worth asserting is that rendering completes and the literal text
    # (parsed as plain characters, not markup) still ends up on the page.
    record = _record(
        target="<script>alert(1)</script>",
        findings=[Finding(title="<img src=x onerror=alert(1)>", detail="<b>bold</b> & stuff")],
    )
    text = _text(pdf.render(record))  # must not raise
    assert "alert(1)" in text
    assert "bold" in text and "stuff" in text


def _attack_session_and_records() -> tuple[AttackSession, list[RunRecord]]:
    r1 = _record(run_id="run1", target="host-a", plugin="network", kill_chain_phase=KillChainPhase.DISCOVERY)
    r2 = _record(
        run_id="run2",
        target="host-b",
        plugin="manual",
        kill_chain_phase=KillChainPhase.LATERAL_MOVEMENT,
        via_target="host-a",
        engagement="eng1",
        findings=[Finding(title="pivoted in", severity="high")],
    )
    session = AttackSession(
        name="chain-1",
        description="test chain",
        engagement="eng1",
        stages=[
            AttackSessionStage(run_id="run1", label="initial recon"),
            AttackSessionStage(run_id="run2", label="lateral move"),
        ],
    )
    return session, [r1, r2]


def test_render_attack_session_produces_a_valid_pdf() -> None:
    session, records = _attack_session_and_records()
    data = pdf.render_attack_session(session, records)
    assert data.startswith(b"%PDF-")
    assert len(pypdf.PdfReader(io.BytesIO(data)).pages) >= 1


def test_render_attack_session_includes_stages_and_metadata() -> None:
    session, records = _attack_session_and_records()
    text = _text(pdf.render_attack_session(session, records))
    assert "Attack Session: chain-1" in text
    assert "test chain" in text
    assert "eng1" in text
    assert "host-a" in text
    assert "host-b" in text
    assert "initial recon" in text
    assert "lateral move" in text
    assert "pivoted in" in text
    assert "host-a" in text  # via_target shown for the pivot stage


def test_render_attack_session_with_no_stages_shows_placeholder() -> None:
    session = AttackSession(name="empty", stages=[])
    text = _text(pdf.render_attack_session(session, []))
    assert "ステージがまだありません" in text
