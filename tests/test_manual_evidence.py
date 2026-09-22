from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.manual_evidence import MANUAL_PLUGIN_NAME, import_manual_run
from pownforge.core.models import Engagement, KillChainPhase, Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore


def _policy_with_target(**overrides) -> ScopePolicy:
    defaults = dict(name="lab", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=[])
    defaults.update(overrides)
    return ScopePolicy(targets={defaults["name"]: Target(**defaults)})


def _policy_with_engagement() -> ScopePolicy:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="host-a", kind=TargetKind.HOST, address="10.0.0.1"))
    policy.add_target(Target(name="host-b", kind=TargetKind.HOST, address="10.0.0.2"))
    policy.add_target(Target(name="host-c", kind=TargetKind.HOST, address="10.0.0.3"))
    policy.add_engagement(Engagement(name="eng1", targets=["host-a", "host-b"]))
    return policy


def test_import_manual_run_persists_evidence_and_output(tmp_path: Path) -> None:
    policy = _policy_with_target()
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(
        policy,
        store,
        "lab",
        command="msfconsole -x 'use exploit/multi/http/apache_mod_cgi_bash_env_exec; run'",
        output="[*] Command shell session 1 opened\nwhoami\nwww-data",
        tool="msfconsole",
        tool_version="Metasploit Framework 6.4",
    )

    assert record.plugin == MANUAL_PLUGIN_NAME
    assert record.target == "lab"
    assert record.output["raw_stdout"].startswith("[*] Command shell session")
    assert record.output["tool"] == "msfconsole"
    assert record.evidence.tool_version == "Metasploit Framework 6.4"
    assert record.evidence.returncode == 0

    reloaded = store.load(record.run_id)
    assert reloaded.evidence.stdout_sha256 == record.evidence.stdout_sha256


def test_import_manual_run_verifies_with_evidence_store(tmp_path: Path) -> None:
    policy = _policy_with_target()
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(policy, store, "lab", command="whoami", output="www-data")

    verification = store.verify(record.run_id)
    assert verification.ok is True


def test_import_manual_run_rejects_target_that_does_not_allow_manual(tmp_path: Path) -> None:
    policy = _policy_with_target(allowed_plugins=["network"])
    store = EvidenceStore(tmp_path / "runs")

    with pytest.raises(PolicyError):
        import_manual_run(policy, store, "lab", command="whoami", output="www-data")


def test_import_manual_run_records_audit_violation_on_rejection(tmp_path: Path) -> None:
    policy = _policy_with_target(allowed_plugins=["network"])
    store = EvidenceStore(tmp_path / "runs")
    audit = AuditStore(tmp_path / "violations")

    with pytest.raises(PolicyError):
        import_manual_run(policy, store, "lab", command="whoami", output="www-data", audit=audit)

    violations = audit.list()
    assert len(violations) == 1
    assert violations[0].plugin == MANUAL_PLUGIN_NAME


def test_import_manual_run_allows_target_that_explicitly_lists_manual(tmp_path: Path) -> None:
    policy = _policy_with_target(allowed_plugins=["network", "manual"])
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(policy, store, "lab", command="whoami", output="www-data")
    assert record.plugin == MANUAL_PLUGIN_NAME


def test_import_manual_run_masks_credential_looking_flags_in_command(tmp_path: Path) -> None:
    policy = _policy_with_target()
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(
        policy,
        store,
        "lab",
        command="hydra -l admin --password hunter2 ssh://127.0.0.1",
        output="1 valid password found",
    )

    assert "hunter2" not in record.evidence.command
    assert "***" in record.evidence.command


def test_import_manual_run_rejects_unregistered_target(tmp_path: Path) -> None:
    policy = ScopePolicy(targets={})
    store = EvidenceStore(tmp_path / "runs")

    with pytest.raises(PolicyError):
        import_manual_run(policy, store, "does-not-exist", command="whoami", output="www-data")


def test_import_manual_run_records_pivot_when_engagement_members(tmp_path: Path) -> None:
    policy = _policy_with_engagement()
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(
        policy,
        store,
        "host-b",
        command="psexec.py admin@10.0.0.2",
        output="[*] Opening SVCManager on 10.0.0.2.....",
        engagement="eng1",
        via_target="host-a",
    )

    assert record.target == "host-b"
    assert record.via_target == "host-a"
    assert record.engagement == "eng1"

    reloaded = store.load(record.run_id)
    assert reloaded.via_target == "host-a"


def test_import_manual_run_rejects_pivot_to_target_outside_engagement(tmp_path: Path) -> None:
    policy = _policy_with_engagement()
    store = EvidenceStore(tmp_path / "runs")

    with pytest.raises(PolicyError):
        import_manual_run(
            policy,
            store,
            "host-c",
            command="psexec.py admin@10.0.0.3",
            output="...",
            engagement="eng1",
            via_target="host-a",
        )


def test_import_manual_run_requires_engagement_and_via_together(tmp_path: Path) -> None:
    policy = _policy_with_engagement()
    store = EvidenceStore(tmp_path / "runs")

    with pytest.raises(PolicyError):
        import_manual_run(policy, store, "host-b", command="whoami", output="www-data", engagement="eng1")

    with pytest.raises(PolicyError):
        import_manual_run(policy, store, "host-b", command="whoami", output="www-data", via_target="host-a")


def test_import_manual_run_without_engagement_leaves_via_target_none(tmp_path: Path) -> None:
    policy = _policy_with_target()
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(policy, store, "lab", command="whoami", output="www-data")
    assert record.via_target is None
    assert record.engagement is None


def test_import_manual_run_records_kill_chain_phase(tmp_path: Path) -> None:
    policy = _policy_with_target()
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(
        policy,
        store,
        "lab",
        command="msfconsole -x 'use exploit/...; run'",
        output="Meterpreter session 1 opened",
        kill_chain_phase=KillChainPhase.INITIAL_ACCESS,
    )

    assert record.kill_chain_phase == KillChainPhase.INITIAL_ACCESS
    reloaded = store.load(record.run_id)
    assert reloaded.kill_chain_phase == KillChainPhase.INITIAL_ACCESS


def test_import_manual_run_defaults_kill_chain_phase_to_none(tmp_path: Path) -> None:
    policy = _policy_with_target()
    store = EvidenceStore(tmp_path / "runs")

    record = import_manual_run(policy, store, "lab", command="whoami", output="www-data")
    assert record.kill_chain_phase is None
