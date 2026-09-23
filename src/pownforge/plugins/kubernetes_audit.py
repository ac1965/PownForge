from __future__ import annotations

import json
import os
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError

# CNI/CSI などクラスタ運用上 privileged/hostPath/hostNetwork が正当に必要な
# system namespace。RBAC/PodSecurity/Network/Imageのチェーン検出すべてで
# ここを除外する (誤検出の主因になるため -- 元になったKubeForgeの
# AGENTS.mdに記録された知見を踏襲)。
EXEMPT_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "tigera-operator",
    "calico-system",
    "calico-apiserver",
}

SENSITIVE_CLUSTER_ROLES = {"cluster-admin"}

# 単体では見逃されがちだが、privileged と同等にホスト脱出を許すケーパビリティ。
HOST_ESCAPE_CAPABILITIES = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT", "SYS_CHROOT"}


def _by_kind(items: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [item for item in items if item.get("kind") == kind]


# ---------------------------------------------------------------------------
# RBAC (kubeforge/scripts/rbac_audit.py を移植)
# ---------------------------------------------------------------------------


def _is_wildcard_rule(rule: dict[str, Any]) -> bool:
    return "*" in rule.get("apiGroups", []) or "*" in rule.get("resources", []) or "*" in rule.get("verbs", [])


def _audit_roles(items: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    findings = []
    for role in items:
        wildcard_rules = [r for r in role.get("rules", []) if _is_wildcard_rule(r)]
        if wildcard_rules:
            findings.append(
                {
                    "kind": kind,
                    "name": role["metadata"]["name"],
                    "namespace": role["metadata"].get("namespace"),
                    "issue": "wildcard-permissions",
                    "rules": wildcard_rules,
                }
            )
    return findings


def _audit_bindings(items: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    findings = []
    for binding in items:
        role_ref = binding.get("roleRef", {})
        if role_ref.get("name") in SENSITIVE_CLUSTER_ROLES:
            findings.append(
                {
                    "kind": kind,
                    "name": binding["metadata"]["name"],
                    "namespace": binding["metadata"].get("namespace"),
                    "issue": f"bound-to-{role_ref.get('name')}",
                    "subjects": binding.get("subjects", []),
                }
            )
    return findings


def _covers_serviceaccount_token_creation(rule: dict[str, Any]) -> bool:
    api_groups = rule.get("apiGroups", [])
    resources = rule.get("resources", [])
    verbs = rule.get("verbs", [])
    api_ok = "*" in api_groups or "" in api_groups
    resource_ok = "*" in resources or "serviceaccounts/token" in resources
    verb_ok = "*" in verbs or "create" in verbs
    return api_ok and resource_ok and verb_ok


def _build_role_rules_index(cluster_roles: list[dict], roles: list[dict]) -> dict:
    index: dict[tuple, list] = {}
    for cr in cluster_roles:
        index[("ClusterRole", None, cr["metadata"]["name"])] = cr.get("rules", [])
    for r in roles:
        index[("Role", r["metadata"]["namespace"], r["metadata"]["name"])] = r.get("rules", [])
    return index


def _collect_privileged_service_accounts(cluster_role_bindings: list[dict], role_bindings: list[dict]) -> set:
    privileged = set()
    for binding in cluster_role_bindings + role_bindings:
        if binding.get("roleRef", {}).get("name") not in SENSITIVE_CLUSTER_ROLES:
            continue
        for subject in binding.get("subjects", []) or []:
            if subject.get("kind") == "ServiceAccount":
                privileged.add((subject.get("namespace"), subject.get("name")))
    return privileged


def find_token_escalation_paths(
    cluster_role_bindings: list[dict],
    role_bindings: list[dict],
    role_rules_index: dict,
    privileged_sas: set,
) -> list[dict[str, Any]]:
    """あるnamespace内で`serviceaccounts/token`のcreate権限を持つServiceAccountが、
    同じnamespace内のcluster-admin付きServiceAccountへ`kubectl create token`で
    なりすませる経路を検出する(RoleBindingはnamespaceスコープに見えるが実質的に
    無意味化する)。"""
    findings: list[dict[str, Any]] = []

    def resource_name_lists_for(rules: list[dict]) -> list[list[str]]:
        return [rule.get("resourceNames", []) for rule in rules if _covers_serviceaccount_token_creation(rule)]

    def escalation_capable_subjects(subjects: list[dict], target_ns: str, target_sa: str) -> list[dict]:
        # system:masters 等の組み込みGroup/Userは既に強い権限を持つ制御プレーン
        # の識別子であり対象外。なりすます先のSA自身・既にprivilegedなSAからの
        # 自己昇格も除外する。
        return [
            s
            for s in (subjects or [])
            if s.get("kind") == "ServiceAccount"
            and not (s.get("namespace") == target_ns and s.get("name") == target_sa)
            and (s.get("namespace"), s.get("name")) not in privileged_sas
        ]

    for binding in cluster_role_bindings:
        role_ref = binding.get("roleRef", {})
        rules = role_rules_index.get(("ClusterRole", None, role_ref.get("name")), [])
        name_lists = resource_name_lists_for(rules)
        if not name_lists:
            continue
        for ns, sa_name in privileged_sas:
            subjects = escalation_capable_subjects(binding.get("subjects"), ns, sa_name)
            if not subjects:
                continue
            if any(not names or sa_name in names for names in name_lists):
                findings.append(
                    {
                        "target_namespace": ns,
                        "target_service_account": sa_name,
                        "via": f"ClusterRoleBinding/{binding['metadata']['name']}",
                        "subjects": subjects,
                    }
                )

    for binding in role_bindings:
        namespace = binding["metadata"]["namespace"]
        role_ref = binding.get("roleRef", {})
        key = (
            ("ClusterRole", None, role_ref.get("name"))
            if role_ref.get("kind") == "ClusterRole"
            else ("Role", namespace, role_ref.get("name"))
        )
        rules = role_rules_index.get(key, [])
        name_lists = resource_name_lists_for(rules)
        if not name_lists:
            continue
        for ns, sa_name in privileged_sas:
            if ns != namespace:
                continue
            subjects = escalation_capable_subjects(binding.get("subjects"), ns, sa_name)
            if not subjects:
                continue
            if any(not names or sa_name in names for names in name_lists):
                findings.append(
                    {
                        "target_namespace": ns,
                        "target_service_account": sa_name,
                        "via": f"RoleBinding/{binding['metadata']['name']}",
                        "subjects": subjects,
                    }
                )

    return findings


def audit_rbac(items: list[dict[str, Any]]) -> dict[str, Any]:
    cluster_roles = _by_kind(items, "ClusterRole")
    roles = _by_kind(items, "Role")
    cluster_role_bindings = _by_kind(items, "ClusterRoleBinding")
    role_bindings = _by_kind(items, "RoleBinding")

    findings = (
        _audit_roles(cluster_roles, "ClusterRole")
        + _audit_roles(roles, "Role")
        + _audit_bindings(cluster_role_bindings, "ClusterRoleBinding")
        + _audit_bindings(role_bindings, "RoleBinding")
    )
    role_rules_index = _build_role_rules_index(cluster_roles, roles)
    privileged_sas = _collect_privileged_service_accounts(cluster_role_bindings, role_bindings)
    token_escalation_paths = find_token_escalation_paths(
        cluster_role_bindings, role_bindings, role_rules_index, privileged_sas
    )
    return {"findings": findings, "token_escalation_paths": token_escalation_paths}


# ---------------------------------------------------------------------------
# Pod Security (kubeforge/scripts/pod_security_audit.py を移植)
# ---------------------------------------------------------------------------


def _has_host_escape_capability(security_context: dict[str, Any]) -> bool:
    if security_context.get("privileged"):
        return True
    caps = (security_context.get("capabilities", {}) or {}).get("add", [])
    return bool(HOST_ESCAPE_CAPABILITIES & set(caps))


def find_breakout_chains(pods: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """privileged/特権capability + hostPath マウント、または + hostPID による
    ノード乗っ取りチェーンを検出する(個別フラグの列挙ではなく組み合わせ)。"""
    chains: list[dict[str, Any]] = []
    for pod in pods:
        spec = pod["spec"]
        namespace = pod["metadata"]["namespace"]
        name = pod["metadata"]["name"]
        if namespace in EXEMPT_NAMESPACES:
            continue

        host_path_volumes = {
            v["name"]: v["hostPath"].get("path") for v in spec.get("volumes", []) or [] if "hostPath" in v
        }
        host_pid = bool(spec.get("hostPID"))

        for container in spec.get("containers", []) or []:
            sc = container.get("securityContext", {}) or {}
            cname = container["name"]
            if not _has_host_escape_capability(sc):
                continue

            for vm in container.get("volumeMounts", []) or []:
                host_path = host_path_volumes.get(vm.get("name"))
                if host_path is None:
                    continue
                chains.append(
                    {
                        "namespace": namespace,
                        "pod": name,
                        "container": cname,
                        "chain": "privileged/特権capability + hostPath マウント",
                        "detail": (
                            f"hostPath '{host_path}' がコンテナ内 '{vm.get('mountPath')}' にマウントされており、"
                            "ノードのファイルシステムに直接読み書きできます (例: chroot でノード root と同等の操作)。"
                        ),
                    }
                )

            if host_pid:
                chains.append(
                    {
                        "namespace": namespace,
                        "pod": name,
                        "container": cname,
                        "chain": "privileged/特権capability + hostPID",
                        "detail": (
                            "hostPID でホストの PID namespace を共有しており、nsenter でホスト上のプロセス "
                            "(PID 1 等) に侵入してノードを乗っ取れます "
                            "(例: nsenter --target 1 --mount --net --pid -- sh)。"
                        ),
                    }
                )
    return chains


def _audit_pod(pod: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    spec = pod["spec"]
    name = pod["metadata"]["name"]
    namespace = pod["metadata"]["namespace"]

    def add(issue: str, severity: str) -> None:
        findings.append({"namespace": namespace, "pod": name, "issue": issue, "severity": severity})

    if spec.get("hostNetwork"):
        add("hostNetwork=true", "high")
    if spec.get("hostPID"):
        add("hostPID=true", "high")
    if spec.get("hostIPC"):
        add("hostIPC=true", "high")

    pod_sc = spec.get("securityContext", {})
    if not pod_sc.get("runAsNonRoot"):
        add("runAsNonRoot not enforced", "low")

    for container in spec.get("containers", []):
        sc = container.get("securityContext", {}) or {}
        cname = container["name"]
        if sc.get("privileged"):
            add(f"container/{cname}: privileged=true", "high")
        caps = (sc.get("capabilities", {}) or {}).get("add", [])
        if caps:
            add(f"container/{cname}: added capabilities {caps}", "high")
        if sc.get("runAsUser") == 0:
            add(f"container/{cname}: runAsUser=0 (root)", "medium")
        if not container.get("resources", {}).get("limits"):
            add(f"container/{cname}: no resource limits", "low")

    for volume in spec.get("volumes", []):
        if "hostPath" in volume:
            add(f"hostPath volume: {volume['hostPath'].get('path')}", "medium")

    return findings


def audit_pod_security(pods: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for pod in pods:
        if pod["metadata"].get("namespace") in EXEMPT_NAMESPACES:
            continue
        findings.extend(_audit_pod(pod))
    return {"findings": findings, "breakout_chains": find_breakout_chains(pods)}


# ---------------------------------------------------------------------------
# Network (kubeforge/scripts/network_audit.py を移植)
# ---------------------------------------------------------------------------


def find_permissive_rules(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """NetworkPolicyは「存在する」だけでは不十分。ルールにfrom/toが無いと、
    その方向は実質的に全許可になる (default-denyのつもりがそうなっていない、
    典型的な誤設定)。"""
    findings = []
    for policy in policies:
        namespace = policy["metadata"]["namespace"]
        name = policy["metadata"]["name"]
        if namespace in EXEMPT_NAMESPACES:
            continue
        spec = policy.get("spec", {})
        policy_types = spec.get("policyTypes", [])

        if "Ingress" in policy_types:
            for rule in spec.get("ingress", []) or []:
                if "from" not in rule:
                    findings.append(
                        {
                            "namespace": namespace,
                            "policy": name,
                            "direction": "Ingress",
                            "detail": "from が指定されていないルールがあり、任意の送信元からの通信を許可しています",
                        }
                    )
        if "Egress" in policy_types:
            for rule in spec.get("egress", []) or []:
                if "to" not in rule:
                    findings.append(
                        {
                            "namespace": namespace,
                            "policy": name,
                            "direction": "Egress",
                            "detail": "to が指定されていないルールがあり、任意の宛先への通信を許可しています",
                        }
                    )
    return findings


def find_hostnetwork_bypass(pods: list[dict[str, Any]], covered_namespaces: set) -> list[dict[str, Any]]:
    """hostNetwork=trueのPodはPodネットワークを経由しないため、NetworkPolicyが
    あっても効果が及ばない。"""
    findings = []
    for pod in pods:
        namespace = pod["metadata"]["namespace"]
        name = pod["metadata"]["name"]
        if namespace in EXEMPT_NAMESPACES:
            continue
        if pod["spec"].get("hostNetwork"):
            has_policy = namespace in covered_namespaces
            findings.append(
                {
                    "namespace": namespace,
                    "pod": name,
                    "has_networkpolicy": has_policy,
                    "detail": (
                        "NetworkPolicy が存在するにもかかわらず適用されません (hostNetwork の Pod には効果がありません)"
                        if has_policy
                        else "NetworkPolicy も存在せず、ホストのネットワークに直接露出しています"
                    ),
                }
            )
    return findings


def audit_network(namespaces: list[dict[str, Any]], policies: list[dict[str, Any]], pods: list[dict[str, Any]]) -> dict[str, Any]:
    ns_names = [ns["metadata"]["name"] for ns in namespaces]
    covered = {p["metadata"]["namespace"] for p in policies}
    uncovered = sorted(set(ns_names) - covered - EXEMPT_NAMESPACES)
    return {
        "namespaces_without_networkpolicy": uncovered,
        "permissive_rules": find_permissive_rules(policies),
        "hostnetwork_bypass": find_hostnetwork_bypass(pods, covered),
    }


# ---------------------------------------------------------------------------
# Image (kubeforge/scripts/image_audit.py を移植。ただしイメージ単位で個別に
# `trivy image`を呼ぶ代わりに、`trivy k8s --report all`が返すPod単位の
# Vulnerabilities集計と突き合わせる -- 1回のtrivy k8s呼び出しで済ませるための
# 意図的な適応)。
# ---------------------------------------------------------------------------


def _pod_escape_factors(pod: dict[str, Any], container: dict[str, Any]) -> list[str]:
    spec = pod["spec"]
    factors = []
    if spec.get("hostNetwork"):
        factors.append("hostNetwork")
    if spec.get("hostPID"):
        factors.append("hostPID")

    sc = container.get("securityContext", {}) or {}
    if sc.get("privileged"):
        factors.append("privileged")
    else:
        caps = (sc.get("capabilities", {}) or {}).get("add", [])
        escape_caps = HOST_ESCAPE_CAPABILITIES & set(caps)
        if escape_caps:
            factors.append(f"capabilities {sorted(escape_caps)}")

    host_path_volumes = {v["name"] for v in spec.get("volumes", []) or [] if "hostPath" in v}
    if any(vm.get("name") in host_path_volumes for vm in container.get("volumeMounts", []) or []):
        factors.append("hostPath マウント")
    return factors


def _trivy_cve_counts_by_pod(trivy_resources: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, int]]:
    counts: dict[tuple[str, str], dict[str, int]] = {}
    for resource in trivy_resources:
        if resource.get("Kind") != "Pod":
            continue
        key = (resource.get("Namespace"), resource.get("Name"))
        bucket = counts.setdefault(key, {"CRITICAL": 0, "HIGH": 0})
        for result in resource.get("Results") or []:
            for vuln in result.get("Vulnerabilities") or []:
                severity = vuln.get("Severity")
                if severity in bucket:
                    bucket[severity] += 1
    return counts


def find_image_chains(pods: list[dict[str, Any]], trivy_resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """「既知の重大脆弱性を持つイメージ」×「そのPodが持つノード脱出手段」を
    突き合わせて検出する。"""
    cve_counts = _trivy_cve_counts_by_pod(trivy_resources)
    chains: list[dict[str, Any]] = []
    for pod in pods:
        namespace = pod["metadata"]["namespace"]
        if namespace in EXEMPT_NAMESPACES:
            continue
        name = pod["metadata"]["name"]
        counts = cve_counts.get((namespace, name))
        if not counts or (counts["CRITICAL"] == 0 and counts["HIGH"] == 0):
            continue

        for container in pod["spec"].get("containers", []) or []:
            escape_factors = _pod_escape_factors(pod, container)
            if not escape_factors:
                continue
            chains.append(
                {
                    "namespace": namespace,
                    "pod": name,
                    "container": container["name"],
                    "image": container.get("image"),
                    "critical": counts["CRITICAL"],
                    "high": counts["HIGH"],
                    "escape_factors": escape_factors,
                    "detail": (
                        f"イメージに CRITICAL {counts['CRITICAL']} 件 / HIGH {counts['HIGH']} 件の既知脆弱性があり、"
                        f"かつ {', '.join(escape_factors)} によりノード脱出手段も持っています。"
                        "イメージ脆弱性のリモート悪用がそのままノード侵害に直結します。"
                    ),
                }
            )
    return chains


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


def _flatten_findings(rbac: dict, pod_security: dict, network: dict, image_chains: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for f in rbac["findings"]:
        scope = f["namespace"] or "cluster-scoped"
        findings.append(
            {
                "title": f"[RBAC] {f['kind']}/{f['name']}: {f['issue']}",
                "severity": "high",
                "detail": f"{scope}: {f['issue']}",
            }
        )
    for p in rbac["token_escalation_paths"]:
        subjects_desc = ", ".join(f"{s.get('kind')}:{s.get('namespace', '-')}/{s.get('name')}" for s in p["subjects"])
        findings.append(
            {
                "title": f"[RBAC chain] token escalation to cluster-admin via {p['via']}",
                "severity": "critical",
                "detail": (
                    f"{subjects_desc} は namespace {p['target_namespace']} の cluster-admin 権限 "
                    f"ServiceAccount {p['target_service_account']} のトークンを発行でき、実質的に "
                    "cluster-admin へ権限昇格できます"
                ),
            }
        )

    for f in pod_security["findings"]:
        findings.append(
            {
                "title": f"[PodSecurity] {f['namespace']}/{f['pod']}: {f['issue']}",
                "severity": f["severity"],
                "detail": f"{f['namespace']}/{f['pod']}: {f['issue']}",
            }
        )
    for c in pod_security["breakout_chains"]:
        findings.append(
            {
                "title": f"[PodSecurity chain] {c['namespace']}/{c['pod']}: {c['chain']}",
                "severity": "critical",
                "detail": f"{c['namespace']}/{c['pod']} (container/{c['container']}): {c['detail']}",
            }
        )

    for ns in network["namespaces_without_networkpolicy"]:
        findings.append(
            {
                "title": f"[Network] {ns}: NetworkPolicy が存在しない",
                "severity": "medium",
                "detail": f"namespace {ns} に NetworkPolicy が存在せず、Pod 間通信が無制限です",
            }
        )
    for r in network["permissive_rules"]:
        findings.append(
            {
                "title": f"[Network chain] {r['namespace']}/{r['policy']} ({r['direction']}) 実効性のないルール",
                "severity": "medium",
                "detail": r["detail"],
            }
        )
    for b in network["hostnetwork_bypass"]:
        findings.append(
            {
                "title": f"[Network chain] {b['namespace']}/{b['pod']}: hostNetwork による NetworkPolicy バイパス",
                "severity": "high",
                "detail": b["detail"],
            }
        )

    for c in image_chains:
        findings.append(
            {
                "title": f"[Image chain] {c['namespace']}/{c['pod']}: CRITICAL {c['critical']} / HIGH {c['high']} + ノード脱出手段",
                "severity": "critical",
                "detail": c["detail"],
            }
        )

    return findings


class KubernetesAuditPlugin(Plugin):
    name = "kubernetes-audit"
    version = "0.1.0"
    description = (
        "One-shot multi-dimensional Kubernetes audit: RBAC/Pod Security/Network/Image "
        "misconfigurations AND the attack chains they combine into (privilege escalation, "
        "node breakout, NetworkPolicy bypass, vulnerable-image + escape-path)."
    )
    required_tool = "kubectl"
    expected_kind = TargetKind.HOST
    kind_hint = "address should be a kubeconfig context name, e.g. kind-kubeforge-lab."

    options_schema = (
        PluginOption(name="namespaces", description="trivy --include-namespaces, comma-separated."),
    )

    def __init__(self) -> None:
        self._resources_path: Path | None = None
        self._trivy_path: Path | None = None

    def check(self) -> bool:
        return shutil.which("kubectl") is not None and shutil.which("trivy") is not None

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            missing = "kubectl" if shutil.which("kubectl") is None else "trivy"
            raise PluginError(f"'{missing}' is not installed or not on PATH")
        self.require_kind(target)

        fd1, resources_raw = tempfile.mkstemp(prefix="pownforge-k8s-audit-resources-", suffix=".json")
        os.close(fd1)
        fd2, trivy_raw = tempfile.mkstemp(prefix="pownforge-k8s-audit-trivy-", suffix=".json")
        os.close(fd2)
        self._resources_path = Path(resources_raw)
        self._trivy_path = Path(trivy_raw)

        kubectl_argv = [
            "kubectl",
            "--context",
            target.address,
            "get",
            "roles,clusterroles,rolebindings,clusterrolebindings,serviceaccounts,pods,networkpolicies,namespaces",
            "--all-namespaces",
            "-o",
            "json",
        ]
        kubectl_cmd = " ".join(shlex.quote(a) for a in kubectl_argv) + f" > {shlex.quote(str(self._resources_path))}"

        # チェーン検出はCRITICAL/HIGHの有無で判定するため、severityは固定
        # (KubeForgeのimage_audit.pyのSEVERITIES_OF_INTERESTと同じ方針)。
        trivy_argv = [
            "trivy",
            "k8s",
            target.address,
            "-f",
            "json",
            "-o",
            str(self._trivy_path),
            "--report",
            "all",
            "--no-progress",
            "--severity",
            "CRITICAL,HIGH",
        ]
        if namespaces := options.get("namespaces"):
            trivy_argv += ["--include-namespaces", str(namespaces)]
        trivy_cmd = " ".join(shlex.quote(a) for a in trivy_argv)

        return ["sh", "-c", f"{kubectl_cmd} && {trivy_cmd}"]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        resources_path, self._resources_path = self._resources_path, None
        trivy_path, self._trivy_path = self._trivy_path, None

        items: list[dict[str, Any]] = []
        if resources_path is not None and resources_path.exists():
            try:
                items = json.loads(resources_path.read_text()).get("items") or []
            except json.JSONDecodeError:
                items = []
            finally:
                resources_path.unlink(missing_ok=True)

        trivy_resources: list[dict[str, Any]] = []
        if trivy_path is not None and trivy_path.exists():
            try:
                trivy_resources = json.loads(trivy_path.read_text()).get("Resources") or []
            except json.JSONDecodeError:
                trivy_resources = []
            finally:
                trivy_path.unlink(missing_ok=True)

        namespaces = _by_kind(items, "Namespace")
        policies = _by_kind(items, "NetworkPolicy")
        pods = _by_kind(items, "Pod")

        rbac = audit_rbac(items)
        pod_security = audit_pod_security(pods)
        network = audit_network(namespaces, policies, pods)
        image_chains = find_image_chains(pods, trivy_resources)

        return {
            "target": target.address,
            "tool": "kubectl+trivy",
            "rbac": rbac,
            "pod_security": pod_security,
            "network": network,
            "image": {"chains": image_chains},
            "resources": {
                "pods": [
                    {
                        "namespace": p["metadata"]["namespace"],
                        "name": p["metadata"]["name"],
                        "node": p["spec"].get("nodeName"),
                    }
                    for p in pods
                ],
            },
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": _flatten_findings(rbac, pod_security, network, image_chains),
        }
