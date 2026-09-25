from __future__ import annotations

import json
from pathlib import Path

from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.evidence.chain import GENESIS_HASH, EvidenceChain
from pownforge.evidence.hashing import sha256_file, sha256_text
from pownforge.evidence.store import EvidenceStore


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
    defaults = dict(target="lab", plugin="network", evidence=Evidence(**evidence_fields), output={})
    defaults.update(overrides)
    return RunRecord(**defaults)


def test_save_appends_a_chain_entry(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    record = _record()

    store.save(record)

    chain = EvidenceChain(tmp_path / "runs")
    entries = chain.entries()
    assert len(entries) == 1
    assert entries[0].run_id == record.run_id
    assert entries[0].prev_chain_hash == GENESIS_HASH
    assert entries[0].seq == 0


def test_re_saving_the_same_run_appends_a_second_linked_entry(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    record = _record()
    store.save(record)

    record.findings.append(Finding(title="Open port", severity="medium"))
    store.save(record)

    chain = EvidenceChain(tmp_path / "runs")
    entries = chain.entries()
    assert len(entries) == 2
    assert entries[0].run_id == entries[1].run_id == record.run_id
    assert entries[1].prev_chain_hash == entries[0].chain_hash
    assert entries[1].seq == 1
    # The content actually differs between the two saves.
    assert entries[0].record_sha256 != entries[1].record_sha256


def test_chain_links_across_different_runs(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    store.save(_record())
    store.save(_record())

    chain = EvidenceChain(tmp_path / "runs")
    entries = chain.entries()
    assert len(entries) == 2
    assert entries[1].prev_chain_hash == entries[0].chain_hash
    assert entries[0].run_id != entries[1].run_id


def test_verify_chain_ok_for_untouched_store(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    store.save(_record())
    store.save(_record())

    result = store.verify_chain()

    assert result.ok is True
    assert result.entries_checked == 2
    assert result.mismatches == []


def test_verify_chain_empty_store_reports_zero_entries(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    result = store.verify_chain()
    assert result.ok is True
    assert result.entries_checked == 0


def test_verify_chain_detects_content_edited_outside_save(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    record = _record()
    store.save(record)

    # Simulate someone editing the run's JSON file directly (not through
    # EvidenceStore.save()) -- e.g. changing a finding's severity by hand.
    run_path = tmp_path / "runs" / f"{record.run_id}.json"
    data = json.loads(run_path.read_text())
    data["target"] = "tampered-target"
    run_path.write_text(json.dumps(data))

    result = store.verify_chain()

    assert result.ok is False
    mismatch = next(m for m in result.mismatches if m.run_id == record.run_id)
    assert mismatch.kind == "content_mismatch"


def test_verify_chain_detects_edited_ledger_entry(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    store.save(_record())
    store.save(_record())

    # Simulate tampering with the ledger itself: edit the first entry's
    # record_sha256 without recomputing the second entry's chain_hash.
    ledger_path = tmp_path / "runs" / "chain.jsonl"
    lines = ledger_path.read_text().splitlines()
    first = json.loads(lines[0])
    first["record_sha256"] = "0" * 64
    lines[0] = json.dumps(first)
    ledger_path.write_text("\n".join(lines) + "\n")

    result = store.verify_chain()

    assert result.ok is False
    assert any(m.kind == "broken_link" and m.seq == 0 for m in result.mismatches)


def test_verify_chain_detects_missing_run_file(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    record = _record()
    store.save(record)

    (tmp_path / "runs" / f"{record.run_id}.json").unlink()

    result = store.verify_chain()

    assert result.ok is False
    assert any(m.kind == "missing_file" and m.run_id == record.run_id for m in result.mismatches)


def test_pre_existing_evidence_dir_without_chain_file_has_nothing_to_verify(tmp_path: Path) -> None:
    """Backward compatibility: an evidence directory populated before this
    feature existed (no chain.jsonl at all) must not be treated as
    tampered -- there's simply no chain recorded yet."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    legacy_record = _record()
    (runs_dir / f"{legacy_record.run_id}.json").write_text(legacy_record.model_dump_json())

    store = EvidenceStore(runs_dir)
    result = store.verify_chain()

    assert result.ok is True
    assert result.entries_checked == 0
    # The legacy run itself still loads fine through the ordinary path.
    assert store.load(legacy_record.run_id).run_id == legacy_record.run_id


def test_chain_hash_is_sha256_of_prev_plus_record_hash(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    record = _record()
    path = store.save(record)

    entry = EvidenceChain(tmp_path / "runs").entries()[0]
    assert entry.chain_hash == sha256_text(GENESIS_HASH + sha256_file(path))
