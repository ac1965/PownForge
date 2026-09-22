from __future__ import annotations

from pownforge.core.models import Finding, FindingStatus, RunRecord, Severity
from pownforge.evidence.store import EvidenceStore


class FindingNotFoundError(RuntimeError):
    """Raised when a run or a finding_id within it doesn't exist."""


def add_finding(
    store: EvidenceStore,
    run_id: str,
    title: str,
    severity: Severity = Severity.INFO,
    detail: str = "",
) -> tuple[RunRecord, Finding]:
    """Attach a human-observed Finding (source="manual") to an existing run.

    Fills the one gap in Finding.source's convention: "tool" findings come
    from a Plugin's own detection and "ai" findings from `analyze`, but
    nothing previously let a human record what they personally observed
    (e.g. a shell obtained via a manually-run exploit, logged via
    `pownforge result import`) as a Finding. Starts at needs-review like
    every other Finding regardless of source -- `pownforge result review`
    still has to be run explicitly to confirm it."""
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        raise FindingNotFoundError(str(exc)) from exc

    finding = Finding(title=title, severity=severity, detail=detail, source="manual")
    record.findings.append(finding)
    store.save(record)
    return record, finding


def review_finding(
    store: EvidenceStore,
    run_id: str,
    finding_id: str,
    status: FindingStatus,
) -> RunRecord:
    """Move a finding to confirmed/false-positive/needs-review and persist it.

    Shared by the CLI `result review` command and the web API's equivalent
    endpoint, so the "load run, find the finding, mutate, save" sequence
    lives in exactly one place.
    """
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        raise FindingNotFoundError(str(exc)) from exc

    for finding in record.findings:
        if finding.finding_id == finding_id:
            finding.status = status
            store.save(record)
            return record

    raise FindingNotFoundError(f"no finding '{finding_id}' on run '{run_id}'")
