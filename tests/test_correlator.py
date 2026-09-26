from __future__ import annotations

import pytest

from pownforge.core.correlator import correlate
from pownforge.core.models import Evidence, Finding, RunRecord, Severity


def _network_run(target: str, open_ports: list[int]) -> RunRecord:
    evidence = Evidence(
        command=["nmap", target],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="a",
        stderr_sha256="b",
    )
    ports = [{"port": str(p), "protocol": "tcp", "state": "open", "service": None} for p in open_ports]
    return RunRecord(
        target=target,
        plugin="network",
        evidence=evidence,
        output={"hosts": [{"address": target, "ports": ports}]},
    )


def _plugin_run(target: str, plugin: str, findings: list[Finding]) -> RunRecord:
    evidence = Evidence(
        command=[plugin, target],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="a",
        stderr_sha256="b",
    )
    return RunRecord(target=target, plugin=plugin, evidence=evidence, output={}, findings=findings)


# --- correlate() contract -------------------------------------------------


def test_correlate_empty_runs_returns_empty() -> None:
    assert correlate([]) == []


def test_correlate_rejects_mixed_targets() -> None:
    runs = [_network_run("a", [22]), _network_run("b", [22])]
    with pytest.raises(ValueError, match="single target"):
        correlate(runs)


def test_correlate_with_no_matching_rules_returns_empty() -> None:
    runs = [_network_run("lab", [8080])]
    assert correlate(runs) == []


# --- rule: high-value port + severe finding --------------------------------


def test_high_value_port_with_severe_finding_matches() -> None:
    runs = [
        _network_run("lab", [3306, 8080]),
        _plugin_run("lab", "container", [Finding(title="CVE-2021-1", severity="critical", source="tool")]),
    ]

    risks = correlate(runs)

    risk = next(r for r in risks if r.rule_id == "high-value-port-with-severe-finding")
    assert "3306" in risk.title
    assert risk.severity == Severity.HIGH
    assert risk.target == "lab"
    assert len(risk.source_finding_ids) == 1


def test_high_value_port_alone_does_not_match() -> None:
    runs = [_network_run("lab", [3306])]
    assert correlate(runs) == []


def test_severe_finding_alone_without_high_value_port_does_not_match() -> None:
    runs = [
        _network_run("lab", [8080]),  # not a high-value port
        _plugin_run("lab", "container", [Finding(title="x", severity="critical", source="tool")]),
    ]
    risk_ids = {r.rule_id for r in correlate(runs)}
    assert "high-value-port-with-severe-finding" not in risk_ids


def test_medium_severity_finding_does_not_trigger_high_value_port_rule() -> None:
    runs = [
        _network_run("lab", [3306]),
        _plugin_run("lab", "container", [Finding(title="x", severity="medium", source="tool")]),
    ]
    risk_ids = {r.rule_id for r in correlate(runs)}
    assert "high-value-port-with-severe-finding" not in risk_ids


# --- rule: leaked secret + remote access -----------------------------------


def test_leaked_secret_with_remote_access_matches() -> None:
    runs = [
        _network_run("lab", [22]),
        _plugin_run("lab", "secrets", [Finding(title="AWS key", severity="high", source="tool")]),
    ]

    risks = correlate(runs)

    risk = next(r for r in risks if r.rule_id == "leaked-secret-with-remote-access")
    assert "22" in risk.title
    assert risk.severity == Severity.HIGH


def test_leaked_secret_without_remote_access_port_does_not_match() -> None:
    runs = [
        _network_run("lab", [8080]),
        _plugin_run("lab", "secrets", [Finding(title="AWS key", severity="high", source="tool")]),
    ]
    risk_ids = {r.rule_id for r in correlate(runs)}
    assert "leaked-secret-with-remote-access" not in risk_ids


def test_remote_access_port_without_secret_does_not_match() -> None:
    runs = [_network_run("lab", [22])]
    risk_ids = {r.rule_id for r in correlate(runs)}
    assert "leaked-secret-with-remote-access" not in risk_ids


# --- rule: multiple plugins confirm critical --------------------------------


def test_multiple_plugins_confirm_critical_matches() -> None:
    runs = [
        _plugin_run("lab", "container", [Finding(title="a", severity="critical", status="confirmed", source="tool")]),
        _plugin_run("lab", "nuclei", [Finding(title="b", severity="critical", status="confirmed", source="tool")]),
    ]

    risks = correlate(runs)

    risk = next(r for r in risks if r.rule_id == "multiple-plugins-confirm-critical")
    assert "container" in risk.title and "nuclei" in risk.title
    assert risk.severity == Severity.CRITICAL
    assert len(risk.source_finding_ids) == 2


def test_single_plugin_confirming_critical_does_not_match() -> None:
    runs = [
        _plugin_run(
            "lab", "container",
            [
                Finding(title="a", severity="critical", status="confirmed", source="tool"),
                Finding(title="b", severity="critical", status="confirmed", source="tool"),
            ],
        ),
    ]
    risk_ids = {r.rule_id for r in correlate(runs)}
    assert "multiple-plugins-confirm-critical" not in risk_ids


def test_needs_review_critical_findings_do_not_match() -> None:
    """This rule deliberately requires status=confirmed -- an unreviewed
    tool-reported critical from two plugins isn't yet a strong enough
    signal to claim a confirmed combined risk."""
    runs = [
        _plugin_run("lab", "container", [Finding(title="a", severity="critical", source="tool")]),
        _plugin_run("lab", "nuclei", [Finding(title="b", severity="critical", source="tool")]),
    ]
    risk_ids = {r.rule_id for r in correlate(runs)}
    assert "multiple-plugins-confirm-critical" not in risk_ids


def test_multiple_rules_can_match_simultaneously() -> None:
    runs = [
        _network_run("lab", [3306, 22]),
        _plugin_run("lab", "secrets", [Finding(title="key", severity="high", source="tool")]),
        _plugin_run("lab", "container", [Finding(title="a", severity="critical", status="confirmed", source="tool")]),
        _plugin_run("lab", "nuclei", [Finding(title="b", severity="critical", status="confirmed", source="tool")]),
    ]

    risk_ids = {r.rule_id for r in correlate(runs)}

    assert risk_ids == {
        "high-value-port-with-severe-finding",
        "leaked-secret-with-remote-access",
        "multiple-plugins-confirm-critical",
    }
