from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.models import (
    PreconditionReport,
    PrimitiveEvidence,
    PrimitiveRunRecord,
    ValidationLevel,
)
from pownforge.evidence.primitive_store import PrimitiveRunStore


def _record(**overrides) -> PrimitiveRunRecord:
    defaults = dict(
        primitive="http.oob-interaction",
        target="lab",
        requested_level=ValidationLevel.VALIDATION,
        level_reached=ValidationLevel.VALIDATION,
        preconditions=PreconditionReport(),
        evidence=PrimitiveEvidence(target="lab", primitive="http.oob-interaction"),
    )
    defaults.update(overrides)
    return PrimitiveRunRecord(**defaults)


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    store = PrimitiveRunStore(tmp_path / "primitive_runs")
    record = _record()
    store.save(record)
    loaded = store.load(record.run_id)
    assert loaded.run_id == record.run_id
    assert loaded.primitive == "http.oob-interaction"
    assert loaded.level_reached == ValidationLevel.VALIDATION


def test_load_missing_raises(tmp_path: Path) -> None:
    store = PrimitiveRunStore(tmp_path / "primitive_runs")
    with pytest.raises(FileNotFoundError, match="no primitive run"):
        store.load("nope")


def test_list_is_newest_first(tmp_path: Path) -> None:
    store = PrimitiveRunStore(tmp_path / "primitive_runs")
    a = _record()
    b = _record()
    store.save(a)
    store.save(b)
    listed = store.list()
    assert {r.run_id for r in listed} == {a.run_id, b.run_id}
    assert listed[0].created_at >= listed[1].created_at
