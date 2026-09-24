"""Shared cross-process exclusive-lock helper (refactor §6.5), extracted
from AttackOperationStore.lock() (core/operation/store.py) now that
ScopePolicy (targets.yaml) and AttackSessionStore need the same
load-mutate-save protection against two concurrent writers (CLI + Web UI,
or two CLI invocations) racing on the same file."""

from __future__ import annotations

import fcntl
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# How long flock_path() waits for a concurrent holder before giving up.
# Bounded, not blocking forever, so a caller gets an explicit TimeoutError
# instead of hanging if a lock is somehow wedged.
DEFAULT_LOCK_TIMEOUT_SECONDS = 5.0
DEFAULT_LOCK_POLL_INTERVAL_SECONDS = 0.05


@contextmanager
def flock_path(
    lock_path: Path,
    *,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_LOCK_POLL_INTERVAL_SECONDS,
) -> Iterator[None]:
    """Exclusive, cross-process lock via fcntl.flock on LOCK_PATH (created
    if missing). Polls with LOCK_NB rather than blocking forever, so a
    wedged holder (e.g. a killed process that somehow left the fd open)
    can't hang every future caller. Raises TimeoutError past
    TIMEOUT_SECONDS; callers wrap that in their own domain exception where
    one already exists (e.g. OperationError)."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"could not acquire the lock at '{lock_path}' within {timeout_seconds}s"
                    )
                time.sleep(poll_interval_seconds)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
