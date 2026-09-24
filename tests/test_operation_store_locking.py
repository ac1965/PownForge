"""P0 §4.6: AttackOperationStore needs locking around its load-mutate-save
sequence so two concurrent updates to the same operation don't race and
silently drop one of them (or corrupt the file -- see also §4.5's atomic
write, which AttackOperationStore.save() now shares with EvidenceStore)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from pownforge.core.operation import AttackNode, AttackOperationStore, OperationError, create_operation


def test_concurrent_updates_to_the_same_operation_do_not_lose_data(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")

    def add_node(i: int) -> None:
        store.update("op", lambda operation: operation.nodes.append(AttackNode(id=f"n{i}", target=f"t{i}")))

    threads = [threading.Thread(target=add_node, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = store.load("op")
    assert len(final.nodes) == 20, "a concurrent update was lost"
    assert {n.id for n in final.nodes} == {f"n{i}" for i in range(20)}


def test_lock_serializes_two_holders_and_releases_after_the_context_exits(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op")

    order: list[str] = []
    started = threading.Event()

    def hold_lock() -> None:
        with store.lock("op"):
            order.append("first-acquired")
            started.set()
            time.sleep(0.2)
            order.append("first-released")

    t = threading.Thread(target=hold_lock)
    t.start()
    started.wait(timeout=2)
    with store.lock("op"):
        order.append("second-acquired")
    t.join()

    assert order == ["first-acquired", "first-released", "second-acquired"]


def test_lock_acquisition_times_out_explicitly_instead_of_hanging_forever(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    store._LOCK_TIMEOUT_SECONDS = 0.2  # keep the test fast
    create_operation(store, "op")

    holder_ready = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with store.lock("op"):
            holder_ready.set()
            release.wait(timeout=5)

    t = threading.Thread(target=hold_lock)
    t.start()
    holder_ready.wait(timeout=2)
    try:
        with pytest.raises(OperationError):
            with store.lock("op"):
                pass
    finally:
        release.set()
        t.join()


def test_operations_with_different_names_do_not_block_each_other(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    create_operation(store, "op-a")
    create_operation(store, "op-b")

    with store.lock("op-a"):
        # A lock on a different operation name must be independent.
        with store.lock("op-b"):
            pass
