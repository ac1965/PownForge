"""refactor §6.5: flock_path is the shared cross-process lock helper
extracted from AttackOperationStore.lock(), now reused by ScopePolicy
(targets.yaml) and AttackSessionStore so CLI and Web can't race on the
same file's load-mutate-save sequence."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from pownforge.core.file_lock import flock_path


def test_lock_serializes_two_holders_and_releases_after_the_context_exits(tmp_path: Path) -> None:
    lock_path = tmp_path / ".thing.lock"
    order: list[str] = []
    started = threading.Event()

    def hold_lock() -> None:
        with flock_path(lock_path):
            order.append("first-acquired")
            started.set()
            time.sleep(0.2)
            order.append("first-released")

    t = threading.Thread(target=hold_lock)
    t.start()
    started.wait(timeout=2)
    with flock_path(lock_path):
        order.append("second-acquired")
    t.join()

    assert order == ["first-acquired", "first-released", "second-acquired"]


def test_lock_acquisition_times_out_explicitly_instead_of_hanging_forever(tmp_path: Path) -> None:
    lock_path = tmp_path / ".thing.lock"
    holder_ready = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with flock_path(lock_path):
            holder_ready.set()
            release.wait(timeout=5)

    t = threading.Thread(target=hold_lock)
    t.start()
    holder_ready.wait(timeout=2)
    try:
        with pytest.raises(TimeoutError):
            with flock_path(lock_path, timeout_seconds=0.2, poll_interval_seconds=0.02):
                pass
    finally:
        release.set()
        t.join()


def test_different_lock_paths_do_not_block_each_other(tmp_path: Path) -> None:
    with flock_path(tmp_path / ".a.lock"):
        with flock_path(tmp_path / ".b.lock"):
            pass
