from __future__ import annotations

from pownforge.core.models import AttackSession, AttackSessionStage, Evidence, RunRecord
from pownforge.reporting import kubernetes_dashboard
from pownforge.reporting.attack_session import render_html

AUDIT_OUTPUT = {
    "rbac": {
        "findings": [],
        "token_escalation_paths": [
            {
                "target_namespace": "vulnerable-lab",
                "target_service_account": "over-permissive-sa",
                "via": "RoleBinding/default-sa-wildcard",
                "subjects": [{"kind": "ServiceAccount", "namespace": "vulnerable-lab", "name": "default"}],
            }
        ],
    },
    "pod_security": {
        "findings": [],
        "breakout_chains": [
            {
                "namespace": "vulnerable-lab",
                "pod": "privileged-host-breakout",
                "container": "shell",
                "chain": "privileged/特権capability + hostPath マウント",
                "detail": "hostPath '/' がマウントされています。",
            }
        ],
    },
    "network": {
        "namespaces_without_networkpolicy": [],
        "permissive_rules": [
            {
                "namespace": "vulnerable-lab",
                "policy": "fake-restrictive",
                "direction": "Ingress",
                "detail": "from が指定されていません",
            }
        ],
        "hostnetwork_bypass": [],
    },
    "image": {
        "chains": [
            {
                "namespace": "vulnerable-lab",
                "pod": "root-no-limits",
                "container": "main",
                "image": "example.com/app:latest",
                "critical": 2,
                "high": 5,
                "escape_factors": ["privileged"],
                "detail": "CRITICAL 2 件 / HIGH 5 件",
            }
        ]
    },
    "resources": {
        "pods": [{"namespace": "vulnerable-lab", "name": "privileged-host-breakout", "node": "kubeforge-lab-worker"}]
    },
}

BENCH_OUTPUT = {
    "pass": 45,
    "fail": 4,
    "warn": 12,
    "info": 3,
    "fails": [{"id": "1.2.5", "desc": "Ensure ... (Automated)"}],
}


def _record(plugin: str, output: dict, run_id: str = "run-1") -> RunRecord:
    evidence = Evidence(
        command=[plugin],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    return RunRecord(run_id=run_id, target="kind-lab", plugin=plugin, evidence=evidence, output=output)


def test_render_section_empty_when_no_k8s_audit_or_bench_records() -> None:
    assert kubernetes_dashboard.render_section([_record("network", {})]) == ""


def test_render_section_renders_chain_cards_and_topology_for_audit_record() -> None:
    html = kubernetes_dashboard.render_section([_record("kubernetes-audit", AUDIT_OUTPUT)])

    assert "Kubernetes 攻撃サーフェス" in html
    assert "over-permissive-sa" in html  # RBAC chain card
    assert "privileged-host-breakout" in html  # Pod Security chain card
    assert "fake-restrictive" in html  # Network permissive rule card
    assert "root-no-limits" in html  # Image chain card
    assert "<svg" in html  # topology, since a breakout_chain has a resolved node
    assert "kubeforge-lab-worker" in html


def test_render_section_renders_bench_bar_for_bench_record() -> None:
    html = kubernetes_dashboard.render_section([_record("kube-bench", BENCH_OUTPUT)])
    assert "kube-bench" in html
    assert "1.2.5" in html
    assert "k8s-bench-bar" in html


def test_render_section_combines_both_records_into_one_dashboard() -> None:
    html = kubernetes_dashboard.render_section(
        [_record("kubernetes-audit", AUDIT_OUTPUT, "run-1"), _record("kube-bench", BENCH_OUTPUT, "run-2")]
    )
    assert "over-permissive-sa" in html
    assert "1.2.5" in html
    # kube-bench KPI card should show up alongside the chain KPIs
    assert "kube-bench" in html


def test_attack_session_render_html_embeds_dashboard_for_k8s_stages() -> None:
    session = AttackSession(
        name="k8s-hardening-check",
        stages=[AttackSessionStage(run_id="run-1"), AttackSessionStage(run_id="run-2")],
    )
    records = [_record("kubernetes-audit", AUDIT_OUTPUT, "run-1"), _record("kube-bench", BENCH_OUTPUT, "run-2")]

    html = render_html(session, records)

    assert "Kubernetes 攻撃サーフェス" in html
    assert "over-permissive-sa" in html


def test_attack_session_render_html_omits_dashboard_for_non_k8s_stages() -> None:
    session = AttackSession(name="web-recon", stages=[AttackSessionStage(run_id="run-1")])
    records = [_record("network", {}, "run-1")]

    html = render_html(session, records)

    assert "Kubernetes 攻撃サーフェス" not in html
