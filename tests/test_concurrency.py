from __future__ import annotations

import os
from pathlib import Path

import pytest

from pownforge.core.concurrency import ConcurrencyError, ConcurrencyGuard


def test_acquire_is_a_noop_when_max_concurrent_is_none(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    with guard.acquire("t", None):
        with guard.acquire("t", None):
            pass  # no ConcurrencyError even though "nested" -- unlimited means unlimited


def test_acquire_allows_up_to_the_limit(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    with guard.acquire("t", 2):
        with guard.acquire("t", 2):
            pass  # 2 concurrent holders, limit is 2: both succeed


def test_acquire_rejects_beyond_the_limit(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    with guard.acquire("t", 1):
        with pytest.raises(ConcurrencyError, match="max_concurrent limit reached"):
            with guard.acquire("t", 1):
                pass


def test_acquire_is_scoped_per_target(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    with guard.acquire("t1", 1):
        with guard.acquire("t2", 1):
            pass  # different targets, no interference


def test_lock_is_released_after_the_context_exits(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    with guard.acquire("t", 1):
        pass
    with guard.acquire("t", 1):
        pass  # the first lock was released, so this succeeds


def test_lock_is_released_even_if_the_body_raises(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    with pytest.raises(ValueError):
        with guard.acquire("t", 1):
            raise ValueError("boom")
    with guard.acquire("t", 1):
        pass  # released despite the exception


def test_stale_lock_from_a_dead_pid_is_ignored(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    target_dir = tmp_path / "active" / "t"
    target_dir.mkdir(parents=True)
    # A PID that (almost certainly) doesn't correspond to a running process.
    dead_pid = 2**30
    (target_dir / "stale.lock").write_text(str(dead_pid))

    with guard.acquire("t", 1):
        pass  # the stale lock doesn't count against the limit


def test_live_lock_from_this_process_counts(tmp_path: Path) -> None:
    guard = ConcurrencyGuard(tmp_path / "active")
    target_dir = tmp_path / "active" / "t"
    target_dir.mkdir(parents=True)
    (target_dir / "live.lock").write_text(str(os.getpid()))

    with pytest.raises(ConcurrencyError):
        with guard.acquire("t", 1):
            pass
