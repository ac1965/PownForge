"""Correlates already-normalized Findings across multiple RunRecords for
the same target, looking for "individually low-risk, together high-risk"
combinations a single plugin's own Finding can't express on its own
(refactor v3 §7).

Pure post-processing over data ScanRunner already produced -- this module
never runs a subprocess, never touches EvidenceStore/AuditStore, and
never triggers a new scan (AGENTS.md's "実際にsubprocessを実行するのは
core/process.py・core/lab.py・ai/ollama.pyに限定"). `correlate()` takes
the list of RunRecord the caller already loaded for one target (same
"caller owns the stores" split as core/engagement_report.py) and returns
zero or more CorrelatedRisk; nothing here decides what to scan or when,
and nothing here writes back into any RunRecord/Finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pownforge.core.models import Finding, FindingStatus, RunRecord, Severity

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# High-value ports worth flagging when paired with another severe finding
# on the same host -- databases, caches, remote administration, and
# orchestration control planes: services rarely meant to be reachable at
# all, and significantly more dangerous once *anything else* on the same
# host is known-vulnerable.
_HIGH_VALUE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    2379: "etcd",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM (TLS)",
    6379: "Redis",
    9200: "Elasticsearch",
    10250: "Kubelet API",
    27017: "MongoDB",
}

_REMOTE_ACCESS_PORTS: dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM (TLS)",
}


@dataclass
class CorrelatedRisk:
    rule_id: str
    title: str
    detail: str
    severity: Severity
    target: str
    source_run_ids: list[str] = field(default_factory=list)
    source_finding_ids: list[str] = field(default_factory=list)


def correlate(runs: list[RunRecord]) -> list[CorrelatedRisk]:
    """RUNS must already be filtered to one target (same contract as
    core/engagement_report.py::collect_engagement's per-target scope) --
    correlating across unrelated targets would produce meaningless pairs.
    Returns zero or more CorrelatedRisk, one per rule that matched. Order
    is stable (declaration order of _RULES), not severity-sorted -- the
    caller sorts if it wants a different order."""
    if not runs:
        return []
    targets = {r.target for r in runs}
    if len(targets) > 1:
        raise ValueError(f"correlate() expects runs for a single target, got {sorted(targets)}")
    target = runs[0].target

    risks: list[CorrelatedRisk] = []
    for rule in _RULES:
        risk = rule(target, runs)
        if risk is not None:
            risks.append(risk)
    return risks


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _open_ports(runs: list[RunRecord], allowed: dict[int, str]) -> dict[int, tuple[str, str]]:
    """port -> (service label, run_id) for every currently-open port in
    ALLOWED found across any `network`-plugin run in RUNS. Reads
    `NetworkPlugin.normalize()`'s own `output["hosts"]` shape directly
    (network scans never produce `_findings` -- there's nothing in
    `.findings` to correlate against for open ports)."""
    found: dict[int, tuple[str, str]] = {}
    for run in runs:
        if run.plugin != "network":
            continue
        for host in run.output.get("hosts") or []:
            for port_info in host.get("ports") or []:
                if port_info.get("state") != "open":
                    continue
                port = _safe_int(port_info.get("port"))
                if port in allowed:
                    found[port] = (allowed[port], run.run_id)
    return found


def _rule_high_value_port_with_severe_finding(target: str, runs: list[RunRecord]) -> CorrelatedRisk | None:
    """"Open high-value port" + "high/critical finding anywhere else on
    the same host" -- the refactor v3 §7 background's own example
    ("特定ポートの開放+特定CVEの存在の組み合わせ"), generalized across any
    plugin's severe finding rather than one hardcoded CVE."""
    high_value = _open_ports(runs, _HIGH_VALUE_PORTS)
    if not high_value:
        return None
    severe: list[tuple[Finding, str]] = [
        (finding, run.run_id)
        for run in runs
        for finding in run.findings
        if _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK[Severity.HIGH]
    ]
    if not severe:
        return None

    port_list = ", ".join(f"{port}/{label}" for port, (label, _) in sorted(high_value.items()))
    finding_titles = "、".join(f.title for f, _ in severe[:3])
    return CorrelatedRisk(
        rule_id="high-value-port-with-severe-finding",
        title=f"高価値ポート({port_list})の開放とhigh以上のfindingが同一ホストに存在",
        detail=(
            f"target '{target}' で管理系/データストア系ポート({port_list})が開放されている状態で、"
            f"重大度high以上のfindingが確認されています({finding_titles})。単体ではそれぞれ許容範囲でも、"
            "組み合わせると当該ポートへの侵入経路として悪用される可能性があるため、優先的に確認してください。"
        ),
        severity=Severity.HIGH,
        target=target,
        source_run_ids=sorted({run_id for _, run_id in high_value.values()} | {run_id for _, run_id in severe}),
        source_finding_ids=[f.finding_id for f, _ in severe],
    )


def _rule_leaked_secret_with_remote_access(target: str, runs: list[RunRecord]) -> CorrelatedRisk | None:
    """`secrets`(gitleaks)由来のfindingと、`network`が見つけたリモート
    アクセス用ポートの組み合わせ -- 典型的な横展開の下地となる組み合わせ。"""
    secret_findings: list[tuple[Finding, str]] = [
        (finding, run.run_id) for run in runs if run.plugin == "secrets" for finding in run.findings
    ]
    if not secret_findings:
        return None
    remote = _open_ports(runs, _REMOTE_ACCESS_PORTS)
    if not remote:
        return None

    port_list = ", ".join(f"{port}/{label}" for port, (label, _) in sorted(remote.items()))
    return CorrelatedRisk(
        rule_id="leaked-secret-with-remote-access",
        title=f"漏洩した可能性のある認証情報と、到達可能なリモートアクセスポート({port_list})が同一ホストに存在",
        detail=(
            f"target '{target}' で{len(secret_findings)}件の認証情報らしき文字列がfinding化されており、"
            f"同じホストでリモートアクセス用ポート({port_list})が開放されています。"
            "漏洩した認証情報がそのアクセス経路で有効かどうかを人手で確認してください"
            "(PownForge自身はこの組み合わせの実悪用を試行しません)。"
        ),
        severity=Severity.HIGH,
        target=target,
        source_run_ids=sorted({run_id for _, run_id in secret_findings} | {run_id for _, run_id in remote.values()}),
        source_finding_ids=[f.finding_id for f, _ in secret_findings],
    )


def _rule_multiple_plugins_confirm_critical(target: str, runs: list[RunRecord]) -> CorrelatedRisk | None:
    """2つ以上の独立したプラグインが、それぞれ`status=confirmed`の
    critical findingを持つ場合 -- 単一ツールの誤検知である可能性が低く、
    複合的な攻撃チェーンとして評価する価値がある組み合わせ。他の2ルールと
    異なりCONFIRMEDのみを対象にする: 「複数の検出結果が実際に確認された」
    という、より強い主張をするルールのため。"""
    critical_by_plugin: dict[str, list[tuple[Finding, str]]] = {}
    for run in runs:
        for finding in run.findings:
            if finding.severity == Severity.CRITICAL and finding.status == FindingStatus.CONFIRMED:
                critical_by_plugin.setdefault(run.plugin, []).append((finding, run.run_id))
    if len(critical_by_plugin) < 2:
        return None

    plugin_list = "、".join(sorted(critical_by_plugin))
    all_pairs = [pair for pairs in critical_by_plugin.values() for pair in pairs]
    return CorrelatedRisk(
        rule_id="multiple-plugins-confirm-critical",
        title=f"{len(critical_by_plugin)}種類の独立した検出手法がcritical重大度を確認済み({plugin_list})",
        detail=(
            f"target '{target}' で複数の独立したプラグイン({plugin_list})が、それぞれcritical重大度の"
            "findingを確認済み(status=confirmed)として記録しています。単一ツールの誤検知である"
            "可能性が低く、組み合わせ悪用による影響範囲の拡大(複合攻撃チェーン)を評価してください。"
        ),
        severity=Severity.CRITICAL,
        target=target,
        source_run_ids=sorted({run_id for _, run_id in all_pairs}),
        source_finding_ids=[f.finding_id for f, _ in all_pairs],
    )


# Declaration order == correlate()'s output order. Add new rules here --
# each takes (target, runs) and returns one CorrelatedRisk or None.
_RULES = (
    _rule_high_value_port_with_severe_finding,
    _rule_leaked_secret_with_remote_access,
    _rule_multiple_plugins_confirm_critical,
)
