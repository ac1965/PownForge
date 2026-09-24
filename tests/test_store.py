from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Evidence, RunRecord
from pownforge.evidence.hashing import sha256_file, sha256_text
from pownforge.evidence.store import EvidenceStore


def _record(output: dict | None = None, evidence_overrides: dict | None = None) -> RunRecord:
    evidence_fields = {
        "command": ["nmap", "127.0.0.1"],
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "returncode": 0,
        "stdout_sha256": "",
        "stderr_sha256": "",
    }
    evidence_fields.update(evidence_overrides or {})
    evidence = Evidence(**evidence_fields)
    return RunRecord(target="lab", plugin="network", evidence=evidence, output=output or {})


def test_save_load_list_roundtrip(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    record = _record(output={"raw_stdout": "hi", "raw_stderr": ""})
    store.save(record)

    loaded = store.load(record.run_id)
    assert loaded.run_id == record.run_id
    assert store.list() == [loaded]


def test_load_unknown_run_raises(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(FileNotFoundError):
        store.load("no-such-run")


def test_verify_matches_when_output_untouched(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    record = _record(
        output={"raw_stdout": "hello", "raw_stderr": "warn"},
        evidence_overrides={
            "stdout_sha256": sha256_text("hello"),
            "stderr_sha256": sha256_text("warn"),
        },
    )
    store.save(record)

    result = store.verify(record.run_id)
    assert result.ok is True
    assert result.stdout.ok is True
    assert result.stderr.ok is True


def test_import_artifact_leaves_no_partial_copy_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs_dir = tmp_path / "runs"
    store = EvidenceStore(runs_dir)
    record = _record(output={"raw_stdout": "hi", "raw_stderr": ""})
    store.save(record)

    source = tmp_path / "proof.pcap"
    source.write_bytes(b"original-bytes")

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full (simulated)")

    monkeypatch.setattr("shutil.copy2", _boom)

    with pytest.raises(OSError):
        store.import_artifact(record.run_id, source)

    dest_dir = runs_dir / "artifacts" / record.run_id
    assert not (dest_dir / source.name).exists()
    assert list(dest_dir.glob(".*.tmp")) == []


def test_import_artifact_copies_file_and_hashes_the_copy(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    store = EvidenceStore(runs_dir)
    record = _record(output={"raw_stdout": "hi", "raw_stderr": ""})
    store.save(record)

    source = tmp_path / "proof.pcap"
    source.write_bytes(b"original-bytes")

    artifact = store.import_artifact(record.run_id, source, description="pcap of the exploit")

    dest = runs_dir / artifact.path
    assert dest.read_bytes() == b"original-bytes"
    assert artifact.sha256 == sha256_file(source)


def test_verify_detects_tampered_output(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    store = EvidenceStore(runs_dir)
    record = _record(
        output={"raw_stdout": "hello", "raw_stderr": ""},
        evidence_overrides={
            "stdout_sha256": sha256_text("hello"),
            "stderr_sha256": sha256_text(""),
        },
    )
    store.save(record)

    # Simulate a careless direct edit of the stored JSON: change the output
    # without touching the recorded hash.
    path = runs_dir / f"{record.run_id}.json"
    data = json.loads(path.read_text())
    data["output"]["raw_stdout"] = "tampered"
    path.write_text(json.dumps(data))

    result = store.verify(record.run_id)
    assert result.ok is False
    assert result.stdout.ok is False
    assert result.stdout.expected != result.stdout.actual
    assert result.stderr.ok is True
