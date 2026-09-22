from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.evidence.audit import AuditStore


def test_record_and_list(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "violations")
    store.record(target="lab-web", plugin="network", reason="not authorized")

    violations = store.list()
    assert len(violations) == 1
    assert violations[0].target == "lab-web"
    assert violations[0].plugin == "network"
    assert violations[0].reason == "not authorized"


def test_list_orders_most_recent_first(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "violations")
    first = store.record(target="a", plugin="network", reason="r1")
    second = store.record(target="b", plugin="network", reason="r2")

    violations = store.list()
    assert [v.violation_id for v in violations] == [second.violation_id, first.violation_id]


def test_load_returns_recorded_violation(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "violations")
    recorded = store.record(target="a", plugin="network", reason="r1")

    loaded = store.load(recorded.violation_id)
    assert loaded.violation_id == recorded.violation_id
    assert loaded.reason == "r1"


def test_load_unknown_id_raises(tmp_path: Path) -> None:
    store = AuditStore(tmp_path / "violations")
    with pytest.raises(FileNotFoundError):
        store.load("no-such-id")
