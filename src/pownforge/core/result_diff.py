"""Compares the CVE IDs found by two already-saved runs (e.g. a before/
after pair around a remediation).

Pure post-processing over data ScanRunner already produced -- same
contract as core/correlator.py: never runs a subprocess, never touches
EvidenceStore/AuditStore, never triggers a new scan. `diff_cves()` takes
two RunRecord the caller already loaded and returns a ResultDiff; nothing
here decides what to scan or when.

Motivated by a real PoC (docs/handbook.md §7 "実機PoC: 検知→是正→再検証")
where comparing raw finding *counts* between a before/after scan was
actively misleading: a version bump resolved every one of the 83 CVEs
found beforehand, yet the after-scan's raw finding count was *higher*
because newly-disclosed CVEs (unrelated to the fix) had accumulated in
the meantime. Comparing the CVE ID *sets* instead of counts is what
actually answers "did the fix work" -- this module makes that comparison
repeatable instead of a one-off script.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pownforge.core.models import RunRecord

# Findings across every plugin follow a "[ID] description" title
# convention (core/finding_utils.py, plugins/_trivy.py etc.), where ID is
# sometimes a CVE and sometimes not (an AVD-xxxx misconfiguration ID, an
# RBAC/PodSecurity label, ...). This narrows to only the CVE ones,
# wherever in the bracket they appear.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")


@dataclass
class ResultDiff:
    run_a: str
    run_b: str
    resolved: list[str]
    still_present: list[str]
    new_only: list[str]


def _cve_ids(run: RunRecord) -> set[str]:
    ids: set[str] = set()
    for finding in run.findings:
        ids.update(_CVE_PATTERN.findall(finding.title))
    return ids


def diff_cves(run_a: RunRecord, run_b: RunRecord) -> ResultDiff:
    """RUN_A is treated as "before", RUN_B as "after" -- resolved = in A
    but not B, still_present = in both, new_only = in B but not A. Order
    within each list is sorted (CVE IDs), not detection order."""
    ids_a = _cve_ids(run_a)
    ids_b = _cve_ids(run_b)
    return ResultDiff(
        run_a=run_a.run_id,
        run_b=run_b.run_id,
        resolved=sorted(ids_a - ids_b),
        still_present=sorted(ids_a & ids_b),
        new_only=sorted(ids_b - ids_a),
    )
