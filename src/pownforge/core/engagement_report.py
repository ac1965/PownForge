"""Assembles a single cross-cutting engagement view over BOTH plugin/manual
runs (RunRecord) and validation-primitive runs (PrimitiveRunRecord).

Pure data collection + filtering (no rendering, no LLM): mirrors the split
used by walkthrough (core loads/filters, reporting/ renders). The value of
this view is one picture of an engagement -- confirmed scan findings and
confirmed primitive claims side by side, plus any residual (un-cleaned)
artifacts a primitive run left behind.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pownforge.core.models import PrimitiveRunRecord, RunRecord


class EngagementReportError(RuntimeError):
    """Raised when a requested engagement scope has no runs to report on."""


@dataclass
class EngagementReport:
    scope_label: str
    runs: list[RunRecord] = field(default_factory=list)  # oldest-first
    primitive_runs: list[PrimitiveRunRecord] = field(default_factory=list)  # oldest-first

    def targets(self) -> list[str]:
        names = {r.target for r in self.runs} | {p.target for p in self.primitive_runs}
        return sorted(names)


def collect_engagement(
    runs: list[RunRecord],
    primitive_runs: list[PrimitiveRunRecord],
    *,
    target: str | None = None,
    engagement_targets: list[str] | None = None,
    scope_label: str,
) -> EngagementReport:
    """Filter and order both record kinds for a scope. Exactly one of
    `target` / `engagement_targets` selects the scope; pass neither to include
    everything. RUNS/PRIMITIVE_RUNS are already-loaded lists (the caller owns
    the stores), matching walkthrough's core/reporting split."""
    if engagement_targets is not None:
        members = set(engagement_targets)
        runs = [r for r in runs if r.target in members or r.via_target in members]
        primitive_runs = [p for p in primitive_runs if p.target in members]
    elif target is not None:
        runs = [r for r in runs if r.target == target]
        primitive_runs = [p for p in primitive_runs if p.target == target]

    if not runs and not primitive_runs:
        raise EngagementReportError(f"no runs found for {scope_label}")

    return EngagementReport(
        scope_label=scope_label,
        runs=sorted(runs, key=lambda r: r.created_at),
        primitive_runs=sorted(primitive_runs, key=lambda p: p.created_at),
    )
