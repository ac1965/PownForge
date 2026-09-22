from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.findings import FindingNotFoundError, add_finding, review_finding
from pownforge.core.models import Evidence, Finding, FindingStatus, RunRecord, Severity
from pownforge.evidence.store import EvidenceStore


def _seed_record(store: EvidenceStore) -> RunRecord:
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    record = RunRecord(
        target="lab",
        plugin="network",
        evidence=evidence,
        output={"raw_stdout": "hi"},
        findings=[Finding(title="Open port 3000", severity="medium")],
    )
    store.save(record)
    return record


def test_review_finding_updates_status_and_persists(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)
    finding_id = seeded.findings[0].finding_id

    updated = review_finding(store, seeded.run_id, finding_id, FindingStatus.CONFIRMED)
    assert updated.findings[0].status == FindingStatus.CONFIRMED

    reloaded = store.load(seeded.run_id)
    assert reloaded.findings[0].status == FindingStatus.CONFIRMED


def test_review_finding_defaults_to_needs_review(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)
    assert seeded.findings[0].status == FindingStatus.NEEDS_REVIEW


def test_review_unknown_run_raises(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(FindingNotFoundError):
        review_finding(store, "does-not-exist", "abc123", FindingStatus.CONFIRMED)


def test_review_unknown_finding_raises(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)
    with pytest.raises(FindingNotFoundError):
        review_finding(store, seeded.run_id, "no-such-id", FindingStatus.CONFIRMED)


def test_add_finding_appends_manual_finding_starting_needs_review(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)

    updated, finding = add_finding(
        store, seeded.run_id, "Got a shell as www-data", severity=Severity.CRITICAL, detail="via CVE-2014-6271"
    )

    assert finding.source == "manual"
    assert finding.status == FindingStatus.NEEDS_REVIEW
    assert finding.severity == Severity.CRITICAL
    assert len(updated.findings) == 2  # kept the existing tool-derived finding too

    reloaded = store.load(seeded.run_id)
    assert any(f.title == "Got a shell as www-data" and f.source == "manual" for f in reloaded.findings)


def test_add_finding_unknown_run_raises(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(FindingNotFoundError):
        add_finding(store, "does-not-exist", "title")
