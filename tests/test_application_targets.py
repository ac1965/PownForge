"""refactor §18 step 1: application/targets.py is the single place
`kind=path` address resolution + ScopePolicy mutation happens, replacing
the duplicated cli.py::target_add / web/routers/targets.py::add_target
(and the lab/lab_kind/lab_provider register/purge commands' own copies of
the same "add_target under lock" shape)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.application.targets import (
    exclude_target,
    include_target,
    register_target,
    remove_target,
)
from pownforge.core.models import Target, TargetKind, TargetPathError
from pownforge.core.policy import PolicyError, ScopePolicy


def _init_config(tmp_path: Path) -> Path:
    config = tmp_path / "targets.yaml"
    ScopePolicy(targets={}).save(config)
    return config


def test_register_target_saves_a_host_target(tmp_path: Path) -> None:
    config = _init_config(tmp_path)
    target = Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1")

    stored = register_target(config, target)

    assert stored.address == "127.0.0.1"
    assert ScopePolicy.load(config).resolve("lab").address == "127.0.0.1"


def test_register_target_resolves_path_kind_address(tmp_path: Path) -> None:
    config = _init_config(tmp_path)
    real_dir = tmp_path / "repo"
    real_dir.mkdir()
    target = Target(name="src", kind=TargetKind.PATH, address=str(real_dir))

    stored = register_target(config, target)

    assert stored.address == str(real_dir.resolve())
    assert ScopePolicy.load(config).resolve("src").address == str(real_dir.resolve())


def test_register_target_raises_target_path_error_for_missing_path(tmp_path: Path) -> None:
    config = _init_config(tmp_path)
    target = Target(name="src", kind=TargetKind.PATH, address=str(tmp_path / "nope"))

    with pytest.raises(TargetPathError):
        register_target(config, target)

    assert ScopePolicy.load(config).list_targets() == []


def test_register_target_raises_policy_error_for_duplicate_name(tmp_path: Path) -> None:
    config = _init_config(tmp_path)
    register_target(config, Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))

    with pytest.raises(PolicyError):
        register_target(config, Target(name="lab", kind=TargetKind.HOST, address="127.0.0.2"))


def test_remove_target_removes_a_registered_target(tmp_path: Path) -> None:
    config = _init_config(tmp_path)
    register_target(config, Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))

    remove_target(config, "lab")

    assert ScopePolicy.load(config).list_targets() == []


def test_remove_target_raises_policy_error_for_unknown_name(tmp_path: Path) -> None:
    config = _init_config(tmp_path)
    with pytest.raises(PolicyError):
        remove_target(config, "nope")


def test_exclude_and_include_target_round_trip(tmp_path: Path) -> None:
    config = _init_config(tmp_path)
    register_target(config, Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))

    excluded = exclude_target(config, "lab", "maintenance window")
    assert excluded.excluded is True
    assert excluded.exclusion_reason == "maintenance window"
    assert ScopePolicy.load(config).resolve("lab").excluded is True

    included = include_target(config, "lab")
    assert included.excluded is False
    assert ScopePolicy.load(config).resolve("lab").excluded is False
