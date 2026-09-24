from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.kubernetes_audit import (
    KubernetesAuditPlugin,
    audit_network,
    audit_pod_security,
    audit_rbac,
    find_breakout_chains,
    find_image_chains,
    find_token_escalation_paths,
)


def _role(name: str, rules: list[dict], namespace: str | None = None, kind: str = "ClusterRole") -> dict:
    meta = {"name": name}
    if namespace:
        meta["namespace"] = namespace
    return {"kind": kind, "metadata": meta, "rules": rules}


def _binding(
    name: str,
    role_name: str,
    subjects: list[dict],
    namespace: str | None = None,
    kind: str = "ClusterRoleBinding",
    role_kind: str = "ClusterRole",
) -> dict:
    meta = {"name": name}
    if namespace:
        meta["namespace"] = namespace
    return {
        "kind": kind,
        "metadata": meta,
        "roleRef": {"kind": role_kind, "name": role_name},
        "subjects": subjects,
    }


def _pod(
    name: str,
    namespace: str,
    *,
    privileged: bool = False,
    capabilities: list[str] | None = None,
    host_path: str | None = None,
    host_pid: bool = False,
    host_network: bool = False,
    image: str = "example.com/app:latest",
) -> dict:
    volumes = []
    volume_mounts = []
    if host_path is not None:
        volumes.append({"name": "hostvol", "hostPath": {"path": host_path}})
        volume_mounts.append({"name": "hostvol", "mountPath": "/host"})
    sc: dict = {}
    if privileged:
        sc["privileged"] = True
    if capabilities:
        sc["capabilities"] = {"add": capabilities}
    return {
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "hostPID": host_pid,
            "hostNetwork": host_network,
            "volumes": volumes,
            "containers": [
                {
                    "name": "main",
                    "image": image,
                    "securityContext": sc,
                    "volumeMounts": volume_mounts,
                }
            ],
        },
    }


# ---------------------------------------------------------------------------
# RBAC: token escalation chain
# ---------------------------------------------------------------------------


def test_find_token_escalation_paths_detects_serviceaccount_token_impersonation() -> None:
    cluster_role_bindings = [
        _binding(
            "over-permissive-sa-cluster-admin",
            "cluster-admin",
            subjects=[{"kind": "ServiceAccount", "namespace": "vulnerable-lab", "name": "over-permissive-sa"}],
        )
    ]
    role = _role(
        "wildcard-role",
        rules=[{"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]}],
        namespace="vulnerable-lab",
        kind="Role",
    )
    role_bindings = [
        _binding(
            "default-sa-wildcard",
            "wildcard-role",
            subjects=[{"kind": "ServiceAccount", "namespace": "vulnerable-lab", "name": "default"}],
            namespace="vulnerable-lab",
            kind="RoleBinding",
            role_kind="Role",
        )
    ]
    role_rules_index = {("Role", "vulnerable-lab", "wildcard-role"): role["rules"]}
    privileged_sas = {("vulnerable-lab", "over-permissive-sa")}

    paths = find_token_escalation_paths(cluster_role_bindings, role_bindings, role_rules_index, privileged_sas)

    assert len(paths) == 1
    assert paths[0]["target_service_account"] == "over-permissive-sa"
    assert paths[0]["via"] == "RoleBinding/default-sa-wildcard"


def test_find_token_escalation_paths_ignores_non_serviceaccount_subjects() -> None:
    """system:masters等の組み込みGroup/Userはワークロード侵害シナリオの対象外。"""
    role_bindings = [
        _binding(
            "admin-group-binding",
            "wildcard-role",
            subjects=[{"kind": "Group", "name": "system:masters"}],
            namespace="vulnerable-lab",
            kind="RoleBinding",
            role_kind="Role",
        )
    ]
    role_rules_index = {
        ("Role", "vulnerable-lab", "wildcard-role"): [
            {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]}
        ]
    }
    privileged_sas = {("vulnerable-lab", "admin-sa")}

    paths = find_token_escalation_paths([], role_bindings, role_rules_index, privileged_sas)
    assert paths == []


def test_audit_rbac_flags_wildcard_rules_and_cluster_admin_bindings() -> None:
    items = [
        _role("wildcard-role", rules=[{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}], kind="ClusterRole"),
        _binding(
            "admin-binding",
            "cluster-admin",
            subjects=[{"kind": "ServiceAccount", "namespace": "vulnerable-lab", "name": "sa"}],
        ),
    ]
    result = audit_rbac(items)
    assert len(result["findings"]) == 2
    issues = {f["issue"] for f in result["findings"]}
    assert "wildcard-permissions" in issues
    assert "bound-to-cluster-admin" in issues


# ---------------------------------------------------------------------------
# Pod Security: breakout chains
# ---------------------------------------------------------------------------


def test_find_breakout_chains_detects_privileged_plus_hostpath_and_hostpid() -> None:
    pods = [_pod("privileged-host-breakout", "vulnerable-lab", privileged=True, host_path="/", host_pid=True)]
    chains = find_breakout_chains(pods)
    kinds = {c["chain"] for c in chains}
    assert "privileged/特権capability + hostPath マウント" in kinds
    assert "privileged/特権capability + hostPID" in kinds
    assert len(chains) == 2


def test_find_breakout_chains_ignores_exempt_system_namespace() -> None:
    """CNI/CSIのDaemonSet等、kube-system上のprivileged+hostPathは正当な構成であり
    誤検出してはいけない。"""
    pods = [_pod("calico-node", "kube-system", privileged=True, host_path="/", host_pid=True)]
    assert find_breakout_chains(pods) == []


def test_find_breakout_chains_requires_both_escape_capability_and_mount() -> None:
    """特権capabilityが無いhostPathマウントだけでは脱出チェーンにならない。"""
    pods = [_pod("harmless", "vulnerable-lab", privileged=False, host_path="/data")]
    assert find_breakout_chains(pods) == []


def test_audit_pod_security_counts_individual_issues() -> None:
    pods = [_pod("root-no-limits", "vulnerable-lab", privileged=False)]
    result = audit_pod_security(pods)
    assert any("runAsNonRoot not enforced" in f["issue"] for f in result["findings"])
    assert any("no resource limits" in f["issue"] for f in result["findings"])


# ---------------------------------------------------------------------------
# Network: permissive rules / hostNetwork bypass
# ---------------------------------------------------------------------------


def test_audit_network_flags_uncovered_namespace_and_permissive_rule_and_hostnetwork_bypass() -> None:
    namespaces = [{"metadata": {"name": "vulnerable-lab"}}, {"metadata": {"name": "no-policy-ns"}}]
    policies = [
        {
            "metadata": {"name": "fake-restrictive", "namespace": "vulnerable-lab"},
            "spec": {"policyTypes": ["Ingress"], "ingress": [{}]},
        }
    ]
    pods = [_pod("exposed", "vulnerable-lab", host_network=True)]

    result = audit_network(namespaces, policies, pods)

    assert result["namespaces_without_networkpolicy"] == ["no-policy-ns"]
    assert len(result["permissive_rules"]) == 1
    assert result["permissive_rules"][0]["direction"] == "Ingress"
    assert len(result["hostnetwork_bypass"]) == 1
    assert result["hostnetwork_bypass"][0]["has_networkpolicy"] is True


def test_audit_network_ignores_exempt_namespaces() -> None:
    namespaces = [{"metadata": {"name": "kube-system"}}]
    result = audit_network(namespaces, policies=[], pods=[])
    assert result["namespaces_without_networkpolicy"] == []


# ---------------------------------------------------------------------------
# Image: CVE x escape-factor chain
# ---------------------------------------------------------------------------


def _trivy_pod_vuln_resource(namespace: str, name: str, critical: int = 0, high: int = 0) -> dict:
    vulns = [{"Severity": "CRITICAL"} for _ in range(critical)] + [{"Severity": "HIGH"} for _ in range(high)]
    return {
        "Namespace": namespace,
        "Kind": "Pod",
        "Name": name,
        "Results": [{"Vulnerabilities": vulns}],
    }


def test_find_image_chains_requires_both_cve_and_escape_factor() -> None:
    pods = [_pod("root-no-limits", "vulnerable-lab", privileged=True, host_pid=True)]
    trivy_resources = [_trivy_pod_vuln_resource("vulnerable-lab", "root-no-limits", critical=2, high=1)]

    chains = find_image_chains(pods, trivy_resources)

    assert len(chains) == 1
    assert chains[0]["critical"] == 2
    assert chains[0]["high"] == 1
    assert "privileged" in chains[0]["escape_factors"]


def test_find_image_chains_skips_pod_without_escape_factors() -> None:
    pods = [_pod("harmless", "vulnerable-lab")]
    trivy_resources = [_trivy_pod_vuln_resource("vulnerable-lab", "harmless", critical=5)]
    assert find_image_chains(pods, trivy_resources) == []


def test_find_image_chains_skips_pod_without_cves() -> None:
    pods = [_pod("privileged-clean-image", "vulnerable-lab", privileged=True)]
    assert find_image_chains(pods, trivy_resources=[]) == []


# ---------------------------------------------------------------------------
# Plugin plumbing: build_command / normalize
# ---------------------------------------------------------------------------


def test_build_command_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubernetesAuditPlugin()
    monkeypatch.setattr(KubernetesAuditPlugin, "check", lambda self: True)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")

    command = plugin.build_command(target, {"namespaces": "vulnerable-lab"}, PluginExecution(tmp_path))

    assert command[0] == "sh" and command[1] == "-c"
    script = command[2]
    assert "kubectl --context kind-kubeforge-lab get" in script
    assert "trivy k8s kind-kubeforge-lab" in script
    assert "--include-namespaces vulnerable-lab" in script
    assert " && " in script


def test_build_command_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubernetesAuditPlugin()
    monkeypatch.setattr(KubernetesAuditPlugin, "check", lambda self: False)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")
    with pytest.raises(PluginError):
        plugin.build_command(target, {}, PluginExecution(tmp_path))


def test_normalize_reads_tempfiles_and_flattens_findings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubernetesAuditPlugin()
    monkeypatch.setattr(KubernetesAuditPlugin, "check", lambda self: True)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")
    execution = PluginExecution(tmp_path)

    plugin.build_command(target, {}, execution)
    resources_path = execution.path("resources.json")
    trivy_path = execution.path("trivy.json")

    resources_path.write_text(
        json.dumps(
            {
                "items": [
                    _pod("privileged-host-breakout", "vulnerable-lab", privileged=True, host_path="/", host_pid=True),
                    {"kind": "Namespace", "metadata": {"name": "vulnerable-lab"}},
                ]
            }
        )
    )
    trivy_path.write_text(json.dumps({"Resources": []}))

    output = plugin.normalize(target, "", "", execution)

    assert output["pod_security"]["breakout_chains"]
    assert output["resources"]["pods"] == [{"namespace": "vulnerable-lab", "name": "privileged-host-breakout", "node": None}]
    titles = [f["title"] for f in output["_findings"]]
    assert any("PodSecurity chain" in t for t in titles)
