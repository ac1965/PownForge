from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.manual_evidence import MANUAL_PLUGIN_NAME, import_manual_run
from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore


def _policy_with_target(**overrides) -> ScopePolicy:
    defaults = dict(name="lab", kind=TargetKind.HOST, address="127.0.0.1", allowed_plugins=[])
    defaults.update(overrides)
    return ScopePolicy(targets={defaults["name"]: Target(**defaults)})


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
