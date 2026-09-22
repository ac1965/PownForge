from __future__ import annotations

from pownforge.core.models import FindingStatus, RunRecord
from pownforge.evidence.store import EvidenceStore


class FindingNotFoundError(RuntimeError):
    """Raised when a run or a finding_id within it doesn't exist."""


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
