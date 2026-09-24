from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from pownforge.core.atomic_write import atomic_write_text
from pownforge.core.file_lock import flock_path
from pownforge.core.operation.model import AttackOperation, OperationError


class AttackOperationStore:
    """One JSON file per AttackOperation. `load`-mutate-`save` is not
    inherently safe against two concurrent callers (CLI + Web UI, or two
    CLI invocations) racing on the same operation -- see `lock()`/`update()`
    and refactor §4.6."""

    # How long lock() waits for a concurrent holder before giving up.
    # Bounded, not blocking forever, so a caller gets an explicit
    # OperationError instead of hanging if a lock is somehow wedged.
    _LOCK_TIMEOUT_SECONDS = 5.0
    _LOCK_POLL_INTERVAL_SECONDS = 0.05

    def __init__(self, operations_dir: Path) -> None:
        self._dir = operations_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def _lock_path(self, name: str) -> Path:
        return self._dir / f".{name}.lock"

    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        """Exclusive, cross-process lock over a load-mutate-save sequence
        for operation NAME, via fcntl.flock on a sibling `.<name>.lock`
        file (core/file_lock.py; refactor §6.5 extracted this into a
        shared helper also used by ScopePolicy and AttackSessionStore).
        Every module-level mutator (add_node, add_action, ...) and
        `update()` hold this for their whole load+save; a bare `save()`
        call outside one of those is the caller's own responsibility."""
        try:
            with flock_path(
                self._lock_path(name),
                timeout_seconds=self._LOCK_TIMEOUT_SECONDS,
                poll_interval_seconds=self._LOCK_POLL_INTERVAL_SECONDS,
            ):
                yield
        except TimeoutError as exc:
            raise OperationError(
                f"could not acquire the update lock for attack operation "
                f"'{name}' within {self._LOCK_TIMEOUT_SECONDS}s"
            ) from exc

    def update(
        self, name: str, mutate: Callable[[AttackOperation], AttackOperation | None]
    ) -> AttackOperation:
        """Load NAME under lock(), call `mutate(operation)`, save the result
        (or the same operation, mutated in place, if MUTATE returns None),
        and return it -- still holding the lock for the whole sequence so
        two concurrent updates can't silently drop one of them."""
        with self.lock(name):
            operation = self.load(name)
            result = mutate(operation)
            operation = result if result is not None else operation
            self.save(operation)
            return operation

    def save(self, operation: AttackOperation) -> Path:
        path = self._dir / f"{operation.name}.json"
        atomic_write_text(path, operation.model_dump_json(indent=2))
        return path

    def load(self, name: str) -> AttackOperation:
        path = self._dir / f"{name}.json"
        if not path.exists():
            raise OperationError(f"no attack operation named '{name}'")
        return AttackOperation.model_validate_json(path.read_text())

    def list(self) -> list[AttackOperation]:
        return [
            AttackOperation.model_validate_json(path.read_text())
            for path in sorted(self._dir.glob("*.json"))
        ]
