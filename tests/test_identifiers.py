"""P0 §4.4: identifier validation, enforced at each Store's creation entry
point. See src/pownforge/core/identifiers.py for the policy rationale and
the existing-data compatibility rule (validated only at creation, never at
load/resolve, so pre-existing records stay loadable regardless of name)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.attack_session import AttackSessionError, AttackSessionStore, create_attack_session
from pownforge.core.identifiers import IdentifierError, resolve_contained_path, validate_identifier
from pownforge.core.lab import LabError, LabManager
from pownforge.core.models import Engagement, Target, TargetKind
from pownforge.core.operation import AttackOperationStore, OperationError, create_operation
from pownforge.core.policy import PolicyError, ScopePolicy


# ---------------------------------------------------------------------------
# The required §4.4 cases, at the unit level
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "../x",
        "a/b",
        "",
        "a" * 101,
        "..",
        ".hidden",
        "trailing.",
        "a\\b",
    ],
)
def test_validate_identifier_rejects_unsafe_names(name: str) -> None:
    with pytest.raises(IdentifierError):
        validate_identifier(name, kind="test")


@pytest.mark.parametrize("name", ["lab-web", "metasploitable2", "op_1", "a.b", "A", "9", "a" * 100])
def test_validate_identifier_accepts_conventional_names(name: str) -> None:
    assert validate_identifier(name, kind="test") == name


# ---------------------------------------------------------------------------
# Wired at each Store's creation entry point
# ---------------------------------------------------------------------------


def test_add_target_rejects_a_path_traversal_name() -> None:
    policy = ScopePolicy(targets={})
    with pytest.raises(PolicyError):
        policy.add_target(Target(name="../evil", kind=TargetKind.HOST, address="127.0.0.1"))


def test_add_engagement_rejects_a_path_traversal_name() -> None:
    policy = ScopePolicy(
        targets={"a": Target(name="a", kind=TargetKind.HOST, address="127.0.0.1")}
    )
    with pytest.raises(PolicyError):
        policy.add_engagement(Engagement(name="../evil", targets=["a"]))


def test_create_operation_rejects_a_path_traversal_name(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    with pytest.raises(OperationError):
        create_operation(store, "../evil")


def test_create_attack_session_rejects_a_path_traversal_name(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    with pytest.raises(AttackSessionError):
        create_attack_session(store, "../evil")


def test_lab_manager_add_rejects_a_path_traversal_name() -> None:
    manager = LabManager(runner=lambda *a, **k: pytest.fail("must not shell out for a rejected name"))
    with pytest.raises(LabError):
        manager.add("../evil", "some-image")


# ---------------------------------------------------------------------------
# Existing-data compatibility: creation is gated, load/list is not
# ---------------------------------------------------------------------------


def test_operation_store_still_loads_a_record_written_before_the_policy_existed(tmp_path: Path) -> None:
    """Simulates data written to disk before identifier validation existed
    (or written directly, bypassing create_operation): AttackOperationStore
    must still be able to load it by name. The policy only gates NEW names
    coming in through create_operation(), never load()."""
    from pownforge.core.operation import AttackOperation

    operations_dir = tmp_path / "operations"
    operations_dir.mkdir(parents=True)
    legacy_name = "legacy op with spaces"  # would fail validate_identifier today
    (operations_dir / f"{legacy_name}.json").write_text(
        AttackOperation(name=legacy_name).model_dump_json()
    )
    store = AttackOperationStore(operations_dir)
    loaded = store.load(legacy_name)
    assert loaded.name == legacy_name


# ---------------------------------------------------------------------------
# refactor §7: a load/update path never calls validate_identifier() (see
# above), so an unvalidated NAME reaching Store.load()/save()/lock() is
# guarded instead by resolve_contained_path()'s "resolved path stays
# inside the store directory" check -- catching path traversal without
# restricting which characters a legitimate existing name may contain.
# ---------------------------------------------------------------------------


def test_resolve_contained_path_accepts_a_name_inside_the_base_dir(tmp_path: Path) -> None:
    resolved = resolve_contained_path(tmp_path, "op1.json", kind="test")
    assert resolved == (tmp_path / "op1.json").resolve()


def test_resolve_contained_path_rejects_traversal_outside_the_base_dir(tmp_path: Path) -> None:
    with pytest.raises(IdentifierError):
        resolve_contained_path(tmp_path, "../../../../etc/passwd", kind="test")


def test_operation_store_load_rejects_a_traversal_name_never_validated_at_creation(
    tmp_path: Path,
) -> None:
    """This name would never reach validate_identifier() at all -- it's
    passed straight to load(), the same way `pownforge operation show
    <name>` does with a raw CLI argument."""
    store = AttackOperationStore(tmp_path / "operations")
    with pytest.raises(OperationError):
        store.load("../../../../etc/passwd")


def test_operation_store_lock_rejects_a_traversal_name(tmp_path: Path) -> None:
    store = AttackOperationStore(tmp_path / "operations")
    with pytest.raises(OperationError):
        with store.lock("../../../../etc/passwd"):
            pass


def test_attack_session_store_load_rejects_a_traversal_name_never_validated_at_creation(
    tmp_path: Path,
) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    with pytest.raises(AttackSessionError):
        store.load("../../../../etc/passwd")


def test_attack_session_store_lock_rejects_a_traversal_name(tmp_path: Path) -> None:
    store = AttackSessionStore(tmp_path / "sessions")
    with pytest.raises(AttackSessionError):
        with store.lock("../../../../etc/passwd"):
            pass
