"""P0 §4.5: EvidenceStore (and AttackOperationStore, which shares the same
helper) must never leave a partial file at the real path if a write fails
partway through."""

from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.atomic_write import atomic_write_text


def test_atomic_write_text_writes_the_full_content(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    atomic_write_text(path, '{"a": 1}')
    assert path.read_text() == '{"a": 1}'


def test_atomic_write_text_leaves_no_partial_file_when_the_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "record.json"
    path.write_text('{"a": "original"}')  # pre-existing content must survive a failed overwrite

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full (simulated)")

    monkeypatch.setattr("os.fsync", _boom)

    with pytest.raises(OSError):
        atomic_write_text(path, '{"a": "new-but-should-never-land"}')

    # The real path is untouched -- still the pre-existing content, never a
    # half-written file.
    assert path.read_text() == '{"a": "original"}'
    # No leftover .record.json.*.tmp sibling.
    assert list(tmp_path.glob(".*.tmp")) == []


def test_atomic_write_text_leaves_no_file_at_all_when_target_did_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "new-record.json"

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full (simulated)")

    monkeypatch.setattr("os.fsync", _boom)

    with pytest.raises(OSError):
        atomic_write_text(path, '{"a": 1}')

    assert not path.exists()
    assert list(tmp_path.glob(".*.tmp")) == []
