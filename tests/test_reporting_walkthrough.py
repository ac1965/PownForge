from __future__ import annotations

from pownforge.core.models import Evidence, Finding, RunRecord, Suggestion
from pownforge.core.walkthrough import Walkthrough
from pownforge.reporting.walkthrough import render_html, render_markdown


def _record(target: str, plugin: str, created_at: str, **overrides) -> RunRecord:
    evidence_fields = {
        "command": [plugin, target],
        "started_at": created_at,
        "finished_at": created_at,
        "returncode": 0,
        "stdout_sha256": "abc",
        "stderr_sha256": "def",
    }
    evidence_fields.update(overrides.pop("evidence_overrides", {}))
    evidence = Evidence(**evidence_fields)
    defaults = dict(target=target, plugin=plugin, created_at=created_at, evidence=evidence, output={})
    defaults.update(overrides)
    return RunRecord(**defaults)


def _walkthrough(**overrides) -> Walkthrough:
    records = overrides.pop("records", None) or [
        _record("lab", "network", "2026-01-01T00:00:00Z", findings=[Finding(title="Open port", severity="low")]),
        _record("lab", "nuclei", "2026-01-02T00:00:00Z"),
    ]
    narrative = overrides.pop("narrative", "First a network scan found an open port, then nuclei found nothing.")
    suggestions = overrides.pop("suggestions", [])
    return Walkthrough(records=records, narrative=narrative, suggestions=suggestions)


def test_render_markdown_includes_meta_narrative_and_runs() -> None:
    output = render_markdown(_walkthrough())
    assert "# Walkthrough: lab (2 runs)" in output
    assert "**Runs:** 2" in output
    assert "2026-01-01T00:00:00" in output and "2026-01-02T00:00:00" in output
    assert "以下はAIが生成した草稿です" in output
    assert "First a network scan found an open port" in output
    assert "## Run 1: lab / network" in output
    assert "## Run 2: lab / nuclei" in output
    assert "Open port" in output
    assert "_No findings recorded for this run._" in output
    assert "## AIの提案(要確認)" in output
    assert "_具体的な提案はありませんでした。_" in output


def test_render_markdown_lists_multiple_targets() -> None:
    records = [
        _record("lab-a", "network", "2026-01-01T00:00:00Z"),
        _record("lab-b", "network", "2026-01-02T00:00:00Z"),
    ]
    output = render_markdown(_walkthrough(records=records))
    assert "# Walkthrough: lab-a, lab-b (2 runs)" in output


def test_render_markdown_orders_findings_by_severity_and_groups_by_status() -> None:
    record = _record(
        "lab",
        "nuclei",
        "2026-01-01T00:00:00Z",
        findings=[
            Finding(title="low one", severity="low", status="confirmed"),
            Finding(title="critical one", severity="critical", status="confirmed"),
        ],
    )
    output = render_markdown(_walkthrough(records=[record]))
    assert output.index("#### 確認済み") < output.index("critical one") < output.index("low one")


def test_render_html_is_self_contained_and_escapes_tool_controlled_fields() -> None:
    record = _record(
        "<script>alert(1)</script>",
        "network",
        "2026-01-01T00:00:00Z",
        findings=[Finding(title="<img src=x onerror=alert(1)>", severity="high")],
    )
    output = render_html(_walkthrough(records=[record], narrative="<script>evil()</script>"))
    assert output.startswith("<!doctype html>")
    assert "<style>" in output
    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "<script>evil()</script>" not in output
    assert "&lt;script&gt;evil()&lt;/script&gt;" in output
    assert "<img src=x onerror" not in output


def test_render_html_includes_severity_badges() -> None:
    output = render_html(_walkthrough())
    assert '<span class="badge">low</span>' in output
    assert 'class="narrative"' in output
    assert "具体的な提案はありませんでした" in output


def test_render_markdown_lists_suggestions_with_and_without_plugin() -> None:
    suggestions = [
        Suggestion(title="Try sqlmap", plugin="sqlmap", rationale="id param looks injectable"),
        Suggestion(title="Review auth flow", plugin=None, rationale="no tool-specific angle"),
    ]
    output = render_markdown(_walkthrough(suggestions=suggestions))
    assert "## AIの提案(要確認)" in output
    assert "**Try sqlmap** (`plugin: sqlmap`) — id param looks injectable" in output
    assert "**Review auth flow** — no tool-specific angle" in output
    assert "_具体的な提案はありませんでした。_" not in output


def test_render_html_lists_suggestions_with_plugin_badge_and_escapes_fields() -> None:
    suggestions = [
        Suggestion(
            title="<script>alert(1)</script>",
            plugin="sqlmap",
            rationale="<b>bold</b> rationale",
        )
    ]
    output = render_html(_walkthrough(suggestions=suggestions))
    assert 'class="suggestion"' in output
    assert '<span class="plugin-badge">sqlmap</span>' in output
    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "&lt;b&gt;bold&lt;/b&gt;" in output
