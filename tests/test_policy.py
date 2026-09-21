from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy


def test_add_and_resolve_target() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab-web", kind=TargetKind.URL, address="http://127.0.0.1:8080"))
    resolved = policy.resolve("lab-web")
    assert resolved.address == "http://127.0.0.1:8080"


def test_resolve_unknown_target_raises() -> None:
    policy = ScopePolicy(targets={})
    with pytest.raises(PolicyError):
        policy.resolve("nope")


def test_add_duplicate_target_raises() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    with pytest.raises(PolicyError):
        policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.2"))


def test_authorize_rejects_disallowed_plugin() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(
        Target(name="lab-net", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=["network"])
    )
    policy.authorize("lab-net", "network")
    with pytest.raises(PolicyError):
        policy.authorize("lab-net", "web")


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab-web", kind=TargetKind.URL, address="http://127.0.0.1:8080"))
    policy.save(config)

    reloaded = ScopePolicy.load(config)
    resolved = reloaded.resolve("lab-web")
    assert resolved.address == "http://127.0.0.1:8080"
