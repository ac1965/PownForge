import threading
from pathlib import Path

import pytest

from pownforge.core.models import Engagement, Target, TargetEnvironment, TargetKind, TargetType
from pownforge.core.policy import PolicyError, ScopePolicy, locked_policy


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


def test_save_is_atomic_and_leaves_original_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "targets.yaml"
    original = ScopePolicy(targets={})
    original.add_target(Target(name="lab-web", kind=TargetKind.URL, address="http://127.0.0.1:8080"))
    original.save(config)
    original_content = config.read_text()

    policy = ScopePolicy.load(config)
    policy.add_target(Target(name="lab-extra", kind=TargetKind.HOST, address="127.0.0.1"))

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full (simulated)")

    monkeypatch.setattr("os.fsync", _boom)

    with pytest.raises(OSError):
        policy.save(config)

    assert config.read_text() == original_content
    assert list(tmp_path.glob(".*.tmp")) == []


def test_locked_policy_saves_the_mutation_on_success(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    ScopePolicy(targets={}).save(config)

    with locked_policy(config) as policy:
        policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))

    reloaded = ScopePolicy.load(config)
    assert reloaded.resolve("lab").address == "127.0.0.1"


def test_locked_policy_does_not_save_when_the_body_raises(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    ScopePolicy(targets={}).save(config)

    with pytest.raises(PolicyError):
        with locked_policy(config) as policy:
            policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
            raise PolicyError("boom")

    reloaded = ScopePolicy.load(config)
    with pytest.raises(PolicyError):
        reloaded.resolve("lab")


def test_locked_policy_serializes_concurrent_writers_without_losing_either(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    ScopePolicy(targets={}).save(config)

    def add(name: str) -> None:
        with locked_policy(config) as policy:
            policy.add_target(Target(name=name, kind=TargetKind.HOST, address="127.0.0.1"))

    threads = [threading.Thread(target=add, args=(f"lab-{i}",)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    reloaded = ScopePolicy.load(config)
    assert {t.name for t in reloaded.list_targets()} == {f"lab-{i}" for i in range(10)}


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


def _policy_with_two_targets(**overrides) -> ScopePolicy:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="host-a", kind=TargetKind.HOST, address="10.0.0.1"))
    policy.add_target(Target(name="host-b", kind=TargetKind.HOST, address="10.0.0.2"))
    return policy


def test_add_engagement_requires_registered_targets() -> None:
    policy = ScopePolicy(targets={})
    with pytest.raises(PolicyError):
        policy.add_engagement(Engagement(name="eng1", targets=["does-not-exist"]))


def test_add_engagement_requires_at_least_one_target() -> None:
    policy = _policy_with_two_targets()
    with pytest.raises(PolicyError):
        policy.add_engagement(Engagement(name="eng1", targets=[]))


def test_add_duplicate_engagement_raises() -> None:
    policy = _policy_with_two_targets()
    policy.add_engagement(Engagement(name="eng1", targets=["host-a"]))
    with pytest.raises(PolicyError):
        policy.add_engagement(Engagement(name="eng1", targets=["host-b"]))


def test_add_engagement_with_production_member_requires_notes() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="host-a", kind=TargetKind.HOST, address="10.0.0.1"))
    policy.add_target(
        Target(
            name="host-b",
            kind=TargetKind.HOST,
            address="10.0.0.2",
            environment=TargetEnvironment.PRODUCTION,
            notes="target-level authorization",
        )
    )
    with pytest.raises(PolicyError):
        policy.add_engagement(Engagement(name="eng1", targets=["host-a", "host-b"]))

    policy.add_engagement(
        Engagement(name="eng1", targets=["host-a", "host-b"], notes="Engagement contract #2026-014")
    )
    assert policy.resolve_engagement("eng1").targets == ["host-a", "host-b"]


def test_resolve_unknown_engagement_raises() -> None:
    policy = ScopePolicy(targets={})
    with pytest.raises(PolicyError):
        policy.resolve_engagement("nope")


def test_authorize_pivot_succeeds_for_engagement_members() -> None:
    policy = _policy_with_two_targets()
    policy.add_engagement(Engagement(name="eng1", targets=["host-a", "host-b"]))
    source, dest = policy.authorize_pivot("eng1", "host-a", "host-b")
    assert source.name == "host-a"
    assert dest.name == "host-b"


def test_authorize_pivot_rejects_target_outside_engagement() -> None:
    policy = _policy_with_two_targets()
    policy.add_target(Target(name="host-c", kind=TargetKind.HOST, address="10.0.0.3"))
    policy.add_engagement(Engagement(name="eng1", targets=["host-a", "host-b"]))
    with pytest.raises(PolicyError):
        policy.authorize_pivot("eng1", "host-a", "host-c")


def test_save_and_load_roundtrip_preserves_engagements(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    policy = _policy_with_two_targets()
    policy.add_engagement(Engagement(name="eng1", targets=["host-a", "host-b"], notes="lab exercise"))
    policy.save(config)

    reloaded = ScopePolicy.load(config)
    engagement = reloaded.resolve_engagement("eng1")
    assert engagement.targets == ["host-a", "host-b"]
    assert engagement.notes == "lab exercise"
    source, dest = reloaded.authorize_pivot("eng1", "host-a", "host-b")
    assert source.name == "host-a"
    assert dest.name == "host-b"


def test_exclude_target_blocks_authorize_even_for_previously_allowed_plugins() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=["network"]))
    policy.authorize("lab", "network")  # allowed before exclusion

    policy.exclude_target("lab", "maintenance window")

    with pytest.raises(PolicyError, match="excluded"):
        policy.authorize("lab", "network")


def test_exclude_target_reason_is_included_in_the_error() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    policy.exclude_target("lab", "stakeholder asked to pause")

    with pytest.raises(PolicyError, match="stakeholder asked to pause"):
        policy.authorize("lab", "network")


def test_include_target_clears_exclusion() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    policy.exclude_target("lab", "temporary")

    policy.include_target("lab")

    policy.authorize("lab", "network")  # no longer raises


def test_exclude_unknown_target_raises() -> None:
    policy = ScopePolicy(targets={})
    with pytest.raises(PolicyError):
        policy.exclude_target("nope")


def test_save_and_load_roundtrip_preserves_exclusion(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    policy.exclude_target("lab", "audit pending")
    policy.save(config)

    reloaded = ScopePolicy.load(config)
    target = reloaded.resolve("lab")
    assert target.excluded is True
    assert target.exclusion_reason == "audit pending"


def test_save_and_load_roundtrip_preserves_max_concurrent(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1", max_concurrent=3))
    policy.save(config)

    reloaded = ScopePolicy.load(config)
    assert reloaded.resolve("lab").max_concurrent == 3
