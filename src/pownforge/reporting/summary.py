from __future__ import annotations

from dataclasses import dataclass

from pownforge.core.models import Finding, FindingStatus, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass(frozen=True)
class FindingsSummary:
    """Aggregate counts behind a report's executive-summary section. Built
    from already-stored Findings only -- it never infers or asserts a
    severity/status itself, just tallies what's already on record."""

    total: int
    confirmed_by_severity: list[tuple[Severity, int]]
    needs_review: int
    false_positive: int

    @property
    def highest_confirmed_severity(self) -> Severity | None:
        return self.confirmed_by_severity[0][0] if self.confirmed_by_severity else None

    @property
    def headline(self) -> str:
        if self.highest_confirmed_severity is not None:
            return f"確認済みの最高重大度: {self.highest_confirmed_severity.value}"
        if self.needs_review:
            return f"確認済みの指摘はまだありません(要確認 {self.needs_review}件、人による検証が必要です)"
        return "指摘事項はありません"


def summarize(findings: list[Finding]) -> FindingsSummary:
    confirmed_counts = {severity: 0 for severity in _SEVERITY_ORDER}
    needs_review = 0
    false_positive = 0
    for finding in findings:
        if finding.status == FindingStatus.CONFIRMED:
            confirmed_counts[finding.severity] += 1
        elif finding.status == FindingStatus.NEEDS_REVIEW:
            needs_review += 1
        elif finding.status == FindingStatus.FALSE_POSITIVE:
            false_positive += 1

    confirmed_by_severity = [
        (severity, count) for severity in _SEVERITY_ORDER if (count := confirmed_counts[severity]) > 0
    ]

    return FindingsSummary(
        total=len(findings),
        confirmed_by_severity=confirmed_by_severity,
        needs_review=needs_review,
        false_positive=false_positive,
    )
