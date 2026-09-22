from __future__ import annotations

from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.reporting.markdown import render


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


def test_render_without_findings_or_analysis_shows_placeholders() -> None:
    output = render(_record())
    assert "_No findings recorded yet._" in output
    assert "`pownforge analyze` を実行すると" in output
    assert "**Tool version:** _unknown_" in output


def test_render_shows_tool_version_when_recorded() -> None:
    output = render(_record(evidence_overrides={"tool_version": "Nmap version 7.991"}))
    assert "**Tool version:** Nmap version 7.991" in output


def test_render_with_findings_lists_them() -> None:
    record = _record(
        findings=[
            Finding(title="Open port 3000", severity="medium", detail="ppp?", source="ai"),
            Finding(title="Manual note", severity="low", detail="checked by hand"),
        ]
    )
    output = render(record)
    assert "**[medium]** (AI推定, `" in output
    assert "Open port 3000 — ppp?" in output
    assert "**[low]** (manual, `" in output
    assert "Manual note — checked by hand" in output
    # both default to needs-review, so they land in the same section
    assert "### 要確認" in output
    assert "### 確認済み" not in output


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
    assert output.index("### 確認済み") < output.index("confirmed one")
    assert output.index("### 要確認") < output.index("pending one")
    assert output.index("### 誤検知として却下") < output.index("dismissed one")
    assert output.index("### 確認済み") < output.index("### 要確認") < output.index(
        "### 誤検知として却下"
    )


def test_render_shows_executive_summary_with_no_findings() -> None:
    output = render(_record())
    assert "## エグゼクティブサマリー" in output
    assert "- **総件数:** 0" in output
    assert "- **確認済み:** 0" in output
    assert "- **総合評価:** 指摘事項はありません" in output


def test_render_shows_executive_summary_with_confirmed_findings() -> None:
    record = _record(
        findings=[
            Finding(title="a", status="confirmed", severity="critical"),
            Finding(title="b", status="confirmed", severity="high"),
            Finding(title="c", status="needs-review"),
        ]
    )
    output = render(record)
    assert "- **総件数:** 3" in output
    assert "- **確認済み:** critical 1 / high 1" in output
    assert "- **要確認(未検証):** 1" in output
    assert "- **総合評価:** 確認済みの最高重大度: critical" in output
    # summary must appear before the detailed Findings section
    assert output.index("## エグゼクティブサマリー") < output.index("## Findings")


def test_render_with_analysis_shows_text_not_placeholder() -> None:
    record = _record(analysis="Looks like a dev server; no confirmed vulnerabilities.")
    output = render(record)
    assert "Looks like a dev server; no confirmed vulnerabilities." in output
    assert "`pownforge analyze` を実行すると" not in output
