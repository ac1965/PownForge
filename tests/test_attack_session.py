from __future__ import annotations

import threading
from pathlib import Path

import pytest

from pownforge.core.attack_session import (
    AttackSessionError,
    AttackSessionStore,
    add_stage,
    create_attack_session,
)
from pownforge.core.models import Evidence, RunRecord
from pownforge.evidence.store import EvidenceStore


def _seed_run(store: EvidenceStore, **overrides) -> RunRecord:
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    defaults = dict(target="lab", plugin="network", evidence=evidence, output={})
    defaults.update(overrides)
    record = RunRecord(**defaults)
    store.save(record)
    return record


def test_create_attack_session_starts_empty(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    session = create_attack_session(store, "op-1", description="test op")
    assert session.name == "op-1"
    assert session.description == "test op"
    assert session.stages == []

    reloaded = store.load("op-1")
    assert reloaded.name == "op-1"


def test_create_duplicate_attack_session_raises(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    create_attack_session(store, "op-1")
    with pytest.raises(AttackSessionError):
        create_attack_session(store, "op-1")


def test_load_unknown_attack_session_raises(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    with pytest.raises(AttackSessionError):
        store.load("nope")


def test_add_stage_appends_in_order(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    evidence = EvidenceStore(tmp_path / "runs")
    create_attack_session(store, "op-1")
    run_a = _seed_run(evidence, plugin="network")
    run_b = _seed_run(evidence, plugin="web")

    add_stage(store, evidence, "op-1", run_a.run_id, label="initial recon")
    session = add_stage(store, evidence, "op-1", run_b.run_id, label="content discovery")

    assert [s.run_id for s in session.stages] == [run_a.run_id, run_b.run_id]
    assert session.stages[0].label == "initial recon"
    assert session.stages[1].label == "content discovery"

    reloaded = store.load("op-1")
    assert len(reloaded.stages) == 2


def test_save_is_atomic_and_leaves_no_partial_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions_dir = tmp_path / "sessions"
    store = AttackSessionStore(sessions_dir)
    session = create_attack_session(store, "op-1", description="test op")
    session.description = "updated"

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full (simulated)")

    monkeypatch.setattr("os.fsync", _boom)

    with pytest.raises(OSError):
        store.save(session)

    reloaded = store.load("op-1")
    assert reloaded.description == "test op"
    assert list(sessions_dir.glob(".*.tmp")) == []


def test_add_stage_serializes_concurrent_writers_without_losing_any_stage(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    evidence = EvidenceStore(tmp_path / "runs")
    create_attack_session(store, "op-1")
    runs = [_seed_run(evidence, plugin=f"plugin-{i}") for i in range(10)]

    threads = [
        threading.Thread(target=add_stage, args=(store, evidence, "op-1", run.run_id))
        for run in runs
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = store.load("op-1")
    assert len(final.stages) == 10, "a concurrent add_stage was lost"
    assert {s.run_id for s in final.stages} == {run.run_id for run in runs}


def test_add_stage_rejects_unknown_run_id(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    evidence = EvidenceStore(tmp_path / "runs")
    create_attack_session(store, "op-1")
    with pytest.raises(AttackSessionError):
        add_stage(store, evidence, "op-1", "does-not-exist")


def test_add_stage_rejects_unknown_session(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    evidence = EvidenceStore(tmp_path / "runs")
    run = _seed_run(evidence)
    with pytest.raises(AttackSessionError):
        add_stage(store, evidence, "nope", run.run_id)


def test_list_sorted_by_name(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    create_attack_session(store, "b-op")
    create_attack_session(store, "a-op")
    assert [s.name for s in store.list()] == ["a-op", "b-op"]


def test_add_stage_never_mutates_the_referenced_run(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    evidence = EvidenceStore(tmp_path / "runs")
    create_attack_session(store, "op-1")
    run = _seed_run(evidence)
    path = tmp_path / "runs" / f"{run.run_id}.json"
    before = path.read_text()

    add_stage(store, evidence, "op-1", run.run_id, label="note")

    assert path.read_text() == before
