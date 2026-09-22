from __future__ import annotations

from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.reporting.html import render


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


def test_render_produces_a_self_contained_html_document() -> None:
    output = render(_record())
    assert output.startswith("<!doctype html>")
    assert "<style>" in output  # no external stylesheet/script references
    assert "<script" not in output


def test_render_without_findings_or_analysis_shows_placeholders() -> None:
    output = render(_record())
    assert "<em>No findings recorded yet.</em>" in output
    assert "`pownforge analyze` を実行すると" in output
    assert "<dd>(unknown)</dd>" in output


def test_render_shows_tool_version_when_recorded() -> None:
    output = render(_record(evidence_overrides={"tool_version": "Nmap version 7.991"}))
    assert "<dd>Nmap version 7.991</dd>" in output


def test_render_with_findings_lists_them_with_severity_badges() -> None:
    record = _record(
        findings=[
            Finding(title="Open port 3000", severity="medium", detail="ppp?", source="ai"),
            Finding(title="Manual note", severity="low", detail="checked by hand"),
        ]
    )
    output = render(record)
    assert '<div class="finding severity-medium">' in output
    assert '<span class="badge">medium</span>' in output
    assert "(AI推定" in output
    assert "Open port 3000</strong> — ppp?" in output
    assert "<h3>要確認</h3>" in output
    assert "<h3>確認済み</h3>" not in output


def test_render_orders_findings_by_severity_desc() -> None:
    record = _record(
        findings=[
            Finding(title="low one", severity="low"),
            Finding(title="critical one", severity="critical"),
            Finding(title="info one", severity="info"),
        ]
    )
    output = render(record)
    assert output.index("critical one") < output.index("low one") < output.index("info one")


def test_render_groups_findings_by_status() -> None:
    record = _record(
        findings=[
            Finding(title="confirmed one", status="confirmed"),
            Finding(title="pending one", status="needs-review"),
            Finding(title="dismissed one", status="false-positive"),
        ]
    )
    output = render(record)
    assert output.index("<h3>確認済み</h3>") < output.index("confirmed one")
    assert output.index("<h3>要確認</h3>") < output.index("pending one")
    assert output.index("<h3>誤検知として却下</h3>") < output.index("dismissed one")


def test_render_with_analysis_shows_text_not_placeholder() -> None:
    record = _record(analysis="Looks like a dev server; no confirmed vulnerabilities.")
    output = render(record)
    assert "Looks like a dev server; no confirmed vulnerabilities." in output
    assert "`pownforge analyze` を実行すると" not in output


def test_render_escapes_html_in_tool_controlled_fields() -> None:
    record = _record(
        target="<script>alert(1)</script>",
        findings=[Finding(title="<img src=x onerror=alert(1)>", detail="<b>bold</b>")],
        output={"raw_stdout": "<script>evil()</script>"},
    )
    output = render(record)
    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "<img src=x" not in output
    assert "&lt;img src=x onerror=alert(1)&gt;" in output
    assert "<script>evil()</script>" not in output
