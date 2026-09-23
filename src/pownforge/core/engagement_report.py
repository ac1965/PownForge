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

    def cve_exposure(self) -> list[CveExposure]:
        """Correlate every CVE tag across the scope into one row: which plugin
        scans detected it, which validation primitives probed it (and the
        highest stage reached, whether a claim was confirmed), and whether a
        human-run exploit step was recorded (with artifacts). The single view
        of "どのCVEが・どこまで成立し・誰が実悪用を確認したか"."""
        cves: list[str] = []
        for record in (*self.runs, *self.primitive_runs):
            for cve in record.cves:
                if cve not in cves:
                    cves.append(cve)

        rows: list[CveExposure] = []
        for cve in sorted(cves):
            scans = [r for r in self.runs if cve in r.cves and r.plugin != "manual"]
            manual = [r for r in self.runs if cve in r.cves and r.plugin == "manual"]
            prims = [p for p in self.primitive_runs if cve in p.cves]
            highest = None
            for p in prims:
                if highest is None or _LEVEL_ORDER[p.level_reached.value] > _LEVEL_ORDER[highest]:
                    highest = p.level_reached.value
            confirmed_validation = any(
                p.evidence and any(c.confidence.value == "confirmed" for c in p.evidence.claims)
                for p in prims
            )
            artifact_count = sum(len(r.artifacts) for r in manual)
            rows.append(
                CveExposure(
                    cve=cve,
                    scan_plugins=sorted({r.plugin for r in scans}),
                    primitive_ids=sorted({p.primitive for p in prims}),
                    highest_validation=highest,
                    confirmed_validation=confirmed_validation,
                    manual_run_ids=[r.run_id for r in manual],
                    manual_artifact_count=artifact_count,
                )
            )
        return rows


_LEVEL_ORDER = {"detection": 0, "validation": 1, "execution": 2}


@dataclass
class CveExposure:
    cve: str
    scan_plugins: list[str]  # plugins that detected/were tagged with this CVE
    primitive_ids: list[str]  # validation primitives probed for it
    highest_validation: str | None  # highest ValidationLevel reached, or None
    confirmed_validation: bool  # a primitive produced a confirmed claim
    manual_run_ids: list[str]  # human-run exploit steps recorded (result import)
    manual_artifact_count: int


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
