from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetEnvironment, TargetKind, TargetType
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


def test_remove_target() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    policy.remove_target("lab")
    with pytest.raises(PolicyError):
        policy.resolve("lab")


def test_remove_unknown_target_raises() -> None:
    policy = ScopePolicy(targets={})
    with pytest.raises(PolicyError):
        policy.remove_target("nope")


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab-web", kind=TargetKind.URL, address="http://127.0.0.1:8080"))
    policy.save(config)

    reloaded = ScopePolicy.load(config)
    resolved = reloaded.resolve("lab-web")
    assert resolved.address == "http://127.0.0.1:8080"


def test_target_defaults_to_local_lab_and_no_type() -> None:
    target = Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1")
    assert target.environment == TargetEnvironment.LOCAL_LAB
    assert target.type is None


def test_add_production_target_without_notes_raises() -> None:
    policy = ScopePolicy(targets={})
    with pytest.raises(PolicyError):
        policy.add_target(
            Target(
                name="prod-web",
                kind=TargetKind.URL,
                address="https://example.internal",
                environment=TargetEnvironment.PRODUCTION,
            )
        )


def test_add_production_target_with_notes_succeeds() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(
        Target(
            name="prod-web",
            kind=TargetKind.URL,
            address="https://example.internal",
            type=TargetType.WEB,
            environment=TargetEnvironment.PRODUCTION,
            notes="Engagement contract #2026-014, authorized 2026-09-20",
        )
    )
    resolved = policy.resolve("prod-web")
    assert resolved.environment == TargetEnvironment.PRODUCTION
    assert resolved.type == TargetType.WEB


def test_save_and_load_roundtrip_preserves_type_and_environment(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    policy = ScopePolicy(targets={})
    policy.add_target(
        Target(
            name="kind-lab",
            kind=TargetKind.HOST,
            address="kind-pownforge-lab",
            type=TargetType.KUBERNETES,
            environment=TargetEnvironment.LOCAL_LAB,
        )
    )
    policy.save(config)

    reloaded = ScopePolicy.load(config)
    resolved = reloaded.resolve("kind-lab")
    assert resolved.type == TargetType.KUBERNETES
    assert resolved.environment == TargetEnvironment.LOCAL_LAB
