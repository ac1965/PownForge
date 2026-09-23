from __future__ import annotations

import fcntl
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# How long to wait for the short-lived ".dirlock" (guards only the
# count-then-create sequence below, never the scan itself) before giving up.
# Non-blocking + poll rather than a plain blocking flock() so a wedged
# holder (e.g. a killed process that somehow left the fd open) can't hang
# every future caller forever.
_DIRLOCK_TIMEOUT_SECONDS = 5.0
_DIRLOCK_POLL_INTERVAL_SECONDS = 0.05


class ConcurrencyError(RuntimeError):
    """Raised when a target's max_concurrent scan limit is already reached,
    or the short-lived bookkeeping lock couldn't be acquired in time."""


class ConcurrencyGuard:
    """Cross-process limit on how many scans run against one target at
    once (Target.max_concurrent, see core/models.py), via lock files under
    <workdir>/active/<target>/. Cross-process because a limit that only
    held within one Python process wouldn't do anything useful -- CLI
    invocations are separate processes, and even the Web UI's JobManager
    runs each scan in its own worker thread of one process, but the point
    of this guard is to also cap scans launched from *different* terminals
    or the CLI running alongside the Web UI.

    A `.dirlock` file (flock'd for the whole check-then-create sequence)
    makes the count-then-acquire atomic -- without it, two processes could
    both see 0 active locks and both proceed past a max_concurrent=1 limit.
    Stale locks left behind by a crashed process are detected by checking
    whether the PID recorded in the lock file is still alive, so a limit
    never gets permanently stuck after a crash."""

    def __init__(self, active_dir: Path) -> None:
        self._dir = active_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def _target_dir(self, target_name: str) -> Path:
        path = self._dir / target_name
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _is_stale(lock_path: Path) -> bool:
        try:
            pid = int(lock_path.read_text().strip())
        except (OSError, ValueError):
            return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False  # process exists, just owned by someone else
        return False

    def _active_count(self, target_dir: Path) -> int:
        count = 0
        for lock_path in target_dir.glob("*.lock"):
            if self._is_stale(lock_path):
                lock_path.unlink(missing_ok=True)
                continue
            count += 1
        return count

    @contextmanager
    def acquire(self, target_name: str, max_concurrent: int | None) -> Iterator[None]:
        """No-op when MAX_CONCURRENT is None (the default: unlimited).
        Otherwise raises ConcurrencyError immediately rather than queueing
        -- a caller that wants to wait/retry can catch it and do so."""
        if max_concurrent is None:
            yield
            return

        target_dir = self._target_dir(target_name)
        lock_path = target_dir / f"{uuid.uuid4().hex[:12]}.lock"
        with open(target_dir / ".dirlock", "a+") as dirlock:
            deadline = time.monotonic() + _DIRLOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(dirlock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ConcurrencyError(
                            f"could not acquire the concurrency lock for target '{target_name}' "
                            f"within {_DIRLOCK_TIMEOUT_SECONDS}s; another process may be stuck holding it"
                        ) from None
                    time.sleep(_DIRLOCK_POLL_INTERVAL_SECONDS)
            try:
                active = self._active_count(target_dir)
                if active >= max_concurrent:
                    raise ConcurrencyError(
                        f"target '{target_name}' already has {active}/{max_concurrent} scan(s) "
                        "running (max_concurrent limit reached); wait for one to finish and retry"
                    )
                lock_path.write_text(str(os.getpid()))
            finally:
                fcntl.flock(dirlock, fcntl.LOCK_UN)

        try:
            yield
        finally:
            lock_path.unlink(missing_ok=True)
