from __future__ import annotations

from pownforge.core.models import Finding, Severity
from pownforge.reporting.summary import summarize


def test_summarize_empty_findings() -> None:
    summary = summarize([])
    assert summary.total == 0
    assert summary.confirmed_by_severity == []
    assert summary.needs_review == 0
    assert summary.false_positive == 0
    assert summary.highest_confirmed_severity is None
    assert summary.headline == "指摘事項はありません"


def test_summarize_counts_by_status() -> None:
    findings = [
        Finding(title="a", status="confirmed", severity="high"),
        Finding(title="b", status="confirmed", severity="high"),
        Finding(title="c", status="needs-review"),
        Finding(title="d", status="false-positive"),
    ]
    summary = summarize(findings)
    assert summary.total == 4
    assert summary.confirmed_by_severity == [(Severity.HIGH, 2)]
    assert summary.needs_review == 1
    assert summary.false_positive == 1


def test_summarize_orders_confirmed_severities_critical_first_and_omits_zero_counts() -> None:
    findings = [
        Finding(title="a", status="confirmed", severity="low"),
        Finding(title="b", status="confirmed", severity="critical"),
        Finding(title="c", status="confirmed", severity="medium"),
    ]
    summary = summarize(findings)
    assert summary.confirmed_by_severity == [
        (Severity.CRITICAL, 1),
        (Severity.MEDIUM, 1),
        (Severity.LOW, 1),
    ]
    assert summary.highest_confirmed_severity == Severity.CRITICAL
    assert summary.headline == "確認済みの最高重大度: critical"


def test_summarize_headline_when_only_needs_review() -> None:
    summary = summarize([Finding(title="a", status="needs-review")])
    assert summary.highest_confirmed_severity is None
    assert "要確認 1件" in summary.headline
