from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import ScopePolicy
from pownforge.evidence.hashing import sha256_file
from pownforge.evidence.store import EvidenceStore


def _policy() -> ScopePolicy:
    p = ScopePolicy(targets={})
    p.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=["manual"]))
    return p


def test_store_import_artifact_copies_and_hashes(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    src = tmp_path / "proof.txt"
    src.write_bytes(b"session transcript")
    art = store.import_artifact("run123", src, description="msf session")
    assert art.type == "manual-artifact"
    assert art.description == "msf session"
    assert art.path == "artifacts/run123/proof.txt"
    assert art.sha256 == sha256_file(src)
    copied = tmp_path / "runs" / "artifacts" / "run123" / "proof.txt"
    assert copied.exists() and copied.read_bytes() == b"session transcript"


def test_store_import_artifact_missing_file(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(FileNotFoundError):
        store.import_artifact("run123", tmp_path / "nope.txt")


def test_import_manual_run_attaches_artifacts(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = tmp_path / "a.pcap"
    a.write_bytes(b"pcapdata")
    b = tmp_path / "b.log"
    b.write_bytes(b"logdata")
    record = import_manual_run(
        _policy(), store, "lab", "msfconsole -x ...", "got shell",
        tool="msfconsole", artifacts=[a, b],
    )
    assert [art.description for art in record.artifacts] == ["a.pcap", "b.log"]
    assert all(art.sha256 for art in record.artifacts)
    # persisted on the reloaded record too
    reloaded = store.load(record.run_id)
    assert len(reloaded.artifacts) == 2
    assert (tmp_path / "runs" / "artifacts" / record.run_id / "a.pcap").exists()


def test_import_manual_run_rejects_missing_artifact_before_saving(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(FileNotFoundError):
        import_manual_run(_policy(), store, "lab", "cmd", "out", artifacts=[tmp_path / "ghost.bin"])
    # nothing was saved
    assert store.list() == []


def test_artifacts_appear_in_reports(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = tmp_path / "proof.txt"
    a.write_bytes(b"x")
    record = import_manual_run(_policy(), store, "lab", "cmd", "out", artifacts=[a])
    from pownforge.reporting.markdown import render as md
    from pownforge.reporting.html import render as html

    assert "## Artifacts" in md(record)
    assert "proof.txt" in md(record)
    assert "Artifacts" in html(record)
    assert record.artifacts[0].sha256 in html(record)
