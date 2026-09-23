from __future__ import annotations

import html as html_escape
from typing import Any

from pownforge.core.models import RunRecord

# Kept visually consistent with reporting/{html,attack_session}.py's light
# theme (same severity palette) rather than importing KubeForge's original
# dark "developer console" dashboard aesthetic wholesale -- this fragment is
# spliced into the same HTML document as the rest of an AttackSession report.
EXTRA_STYLE = """
.k8s-dashboard { margin: 2rem 0; padding: 1rem 1.25rem; border: 1px solid #ddd; border-radius: 8px; background: #fafafa; }
.k8s-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: .6rem; margin: .75rem 0 1.25rem; }
.k8s-kpi { background: white; border: 1px solid #ddd; border-radius: 6px; padding: .5rem .7rem; }
.k8s-kpi .label { font-size: .7rem; color: #666; text-transform: uppercase; letter-spacing: .03em; }
.k8s-kpi .num { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1.3rem; font-weight: 700; }
.k8s-kpi.clean .num { color: #27ae60; }
.k8s-kpi.chain .num { color: #c0392b; }
.k8s-chain-card { background: white; border: 1px solid #ddd; border-left: 4px solid #c0392b; border-radius: 4px;
                   padding: .5rem .75rem; margin-bottom: .5rem; font-size: .85rem; }
.k8s-chain-card .title { font-weight: 600; }
.k8s-chain-card .source { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .72rem; color: #777; }
.k8s-empty { font-size: .82rem; color: #27ae60; }
.k8s-topology { width: 100%; height: auto; border: 1px solid #ddd; border-radius: 6px; background: white; margin: .5rem 0 1rem; }
.k8s-bench-bar { display: flex; height: 10px; border-radius: 5px; overflow: hidden; background: #eee; margin: .4rem 0; }
.k8s-bench-bar .seg.pass { background: #27ae60; }
.k8s-bench-bar .seg.warn { background: #f1c40f; }
.k8s-bench-bar .seg.fail { background: #c0392b; }
.k8s-bench-fail { font-size: .8rem; margin: .15rem 0; }
.k8s-bench-fail .id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #c0392b; margin-right: .5rem; }
"""


def _esc(value: object) -> str:
    return html_escape.escape(str(value))


def _kpi(label: str, value: int, kind: str) -> str:
    cls = "chain" if value else "clean"
    return (
        f'<div class="k8s-kpi {cls}"><div class="label">{_esc(label)}</div>'
        f'<div class="num">{value}</div><div class="label">{_esc(kind)}</div></div>'
    )


def _chain_card(title: str, source: str, detail: str) -> str:
    return (
        f'<div class="k8s-chain-card"><div class="title">{_esc(title)}</div>'
        f'<div class="source">{_esc(source)}</div><div>{_esc(detail)}</div></div>'
    )


def _render_chain_cards(items: list[dict[str, Any]], title_fn, source_fn, detail_fn) -> str:
    if not items:
        return '<p class="k8s-empty">検出されたチェーンはありません。</p>'
    return "".join(_chain_card(title_fn(i), source_fn(i), detail_fn(i)) for i in items)


def _topology_svg(audit_output: dict[str, Any]) -> str:
    """namespace行/node行の簡易オートレイアウトでトポロジー図を組み立てる。
    KubeForgeのgenerate_dashboard.py::build_topology()の簡略移植 -- pods_by_key
    を別途kubectl呼び出しで取る代わりに、kubernetes-auditのoutput.resources.pods
    (kubectl get pods呼び出しの副産物として既に取得済み)をそのまま使う。"""
    pods_by_key = {(p["namespace"], p["name"]): p.get("node") for p in audit_output.get("resources", {}).get("pods", [])}

    ns_labels: dict[str, list[str]] = {}
    arrows: list[dict[str, Any]] = []
    seen: set = set()

    for c in audit_output.get("pod_security", {}).get("breakout_chains", []):
        key = (c["namespace"], c["pod"])
        node = pods_by_key.get(key)
        ns_labels.setdefault(c["namespace"], [])
        tag = f"{c['pod']} [breakout]"
        if tag not in ns_labels[c["namespace"]]:
            ns_labels[c["namespace"]].append(tag)
        arrow_key = (c["namespace"], c["pod"], node, "breakout")
        if node and arrow_key not in seen:
            seen.add(arrow_key)
            arrows.append({"ns": c["namespace"], "node": node, "label": "privileged breakout", "solid": True})

    for b in audit_output.get("network", {}).get("hostnetwork_bypass", []):
        key = (b["namespace"], b["pod"])
        node = pods_by_key.get(key)
        ns_labels.setdefault(b["namespace"], [])
        tag = f"{b['pod']} [hostNetwork]"
        if tag not in ns_labels[b["namespace"]]:
            ns_labels[b["namespace"]].append(tag)
        arrow_key = (b["namespace"], b["pod"], node, "hostnetwork")
        if node and arrow_key not in seen:
            seen.add(arrow_key)
            arrows.append({"ns": b["namespace"], "node": node, "label": "hostNetwork", "solid": False})

    for c in audit_output.get("image", {}).get("chains", []):
        ns_labels.setdefault(c["namespace"], [])
        tag = f"{c['pod']} [image]"
        if tag not in ns_labels[c["namespace"]]:
            ns_labels[c["namespace"]].append(tag)

    if not ns_labels:
        return ""

    nodes_in_use = sorted({a["node"] for a in arrows})

    ns_boxes = {}
    x = 20
    y_ns = 40
    h_ns = 110
    for ns, labels in ns_labels.items():
        w = max(180, 8 * max((len(s) for s in [ns] + labels), default=10) + 20)
        ns_boxes[ns] = {"x": x, "y": y_ns, "w": w, "h": h_ns, "labels": labels}
        x += w + 20
    total_w = max(x + 10, 500)

    node_boxes = {}
    x = 20
    y_node = y_ns + h_ns + 90
    h_node = 60
    for n in nodes_in_use:
        node_boxes[n] = {"x": x, "y": y_node, "w": 180, "h": h_node}
        x += 200
    total_w = max(total_w, x + 10)
    total_h = y_node + h_node + 20 if nodes_in_use else y_ns + h_ns + 20
    boundary_y = y_ns + h_ns + 20

    svg = [f'<svg class="k8s-topology" viewBox="0 0 {total_w} {total_h}" role="img" aria-label="namespaceとノードにまたがる攻撃経路">']
    svg.append(
        '<defs><marker id="k8sArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" '
        'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#c0392b"/></marker></defs>'
    )
    for ns, box in ns_boxes.items():
        svg.append(
            f'<rect x="{box["x"]}" y="{box["y"]}" width="{box["w"]}" height="{box["h"]}" rx="8" '
            f'fill="none" stroke="#c0392b" stroke-width="1.5" stroke-dasharray="5 3"/>'
        )
        svg.append(f'<text x="{box["x"]+10}" y="{box["y"]+20}" font-size="12" font-weight="700" fill="#1a1a1a">{_esc(ns)}</text>')
        ly = box["y"] + 38
        for label in box["labels"]:
            svg.append(f'<text x="{box["x"]+10}" y="{ly}" font-size="9.5" fill="#555">・{_esc(label)}</text>')
            ly += 16

    if nodes_in_use:
        svg.append(
            f'<line x1="10" y1="{boundary_y}" x2="{total_w-10}" y2="{boundary_y}" '
            f'stroke="#ccc" stroke-width="1.5" stroke-dasharray="3 4"/>'
        )
        for n, box in node_boxes.items():
            svg.append(
                f'<rect x="{box["x"]}" y="{box["y"]}" width="{box["w"]}" height="{box["h"]}" rx="8" '
                f'fill="#c0392b" fill-opacity="0.08" stroke="#c0392b" stroke-width="1.5"/>'
            )
            svg.append(f'<text x="{box["x"]+10}" y="{box["y"]+24}" font-size="12" font-weight="700" fill="#c0392b">{_esc(n)}</text>')
            svg.append(f'<text x="{box["x"]+10}" y="{box["y"]+42}" font-size="9.5" fill="#c0392b">侵害</text>')

        for i, a in enumerate(arrows):
            src = ns_boxes.get(a["ns"])
            dst = node_boxes.get(a["node"])
            if not src or not dst:
                continue
            sx, sy = src["x"] + src["w"] / 2 + i * 10, src["y"] + src["h"]
            dx, dy = dst["x"] + dst["w"] / 2, dst["y"]
            dash = "" if a["solid"] else ' stroke-dasharray="5 3"'
            svg.append(
                f'<path d="M{sx:.0f},{sy} C {sx:.0f},{(sy+dy)/2:.0f} {dx:.0f},{(sy+dy)/2:.0f} {dx:.0f},{dy}" '
                f'fill="none" stroke="#c0392b" stroke-width="2"{dash} marker-end="url(#k8sArrow)"/>'
            )
    svg.append("</svg>")
    return "\n".join(svg)


def render_section(records: list[RunRecord]) -> str:
    """kubernetes-audit / kube-bench のrunがsession内にあれば、KPIカード・
    攻撃チェーンカード・トポロジー図・CISベンチマークをまとめたHTML断片を
    返す。どちらも無ければ空文字列(既存のAttackSession reportの見た目は
    変わらない)。"""
    audit_record = next((r for r in records if r.plugin == "kubernetes-audit"), None)
    bench_record = next((r for r in records if r.plugin == "kube-bench"), None)
    if audit_record is None and bench_record is None:
        return ""

    parts = ['<div class="k8s-dashboard">', "<h2>Kubernetes 攻撃サーフェス</h2>"]

    if audit_record is not None:
        output = audit_record.output
        rbac_chains = len(output.get("rbac", {}).get("token_escalation_paths", []))
        podsec_chains = len(output.get("pod_security", {}).get("breakout_chains", []))
        net_chains = len(output.get("network", {}).get("permissive_rules", [])) + len(
            output.get("network", {}).get("hostnetwork_bypass", [])
        )
        image_chains = len(output.get("image", {}).get("chains", []))

        parts.append('<div class="k8s-kpis">')
        parts.append(_kpi("RBAC", rbac_chains, "chain"))
        parts.append(_kpi("Pod Security", podsec_chains, "chain"))
        parts.append(_kpi("Network", net_chains, "chain"))
        parts.append(_kpi("Image", image_chains, "chain"))
        if bench_record is not None:
            parts.append(_kpi("kube-bench", bench_record.output.get("fail", 0), "FAIL"))
        parts.append("</div>")

        topology = _topology_svg(output)
        if topology:
            parts.append("<h3>トポロジー: namespace / ノード境界をどう越えたか</h3>")
            parts.append(topology)

        parts.append("<h3>RBAC — ServiceAccount トークンなりすましによる権限昇格</h3>")
        parts.append(
            _render_chain_cards(
                output.get("rbac", {}).get("token_escalation_paths", []),
                lambda p: f"{p['target_service_account']} (cluster-admin) への昇格",
                lambda p: f"via {p['via']} / namespace {p['target_namespace']}",
                lambda p: ", ".join(f"{s.get('kind')}:{s.get('namespace', '-')}/{s.get('name')}" for s in p["subjects"]),
            )
        )

        parts.append("<h3>Pod Security — コンテナ → ノード乗っ取り</h3>")
        parts.append(
            _render_chain_cards(
                output.get("pod_security", {}).get("breakout_chains", []),
                lambda c: f"{c['pod']}: {c['chain']}",
                lambda c: f"{c['namespace']} / {c['pod']} (container: {c['container']})",
                lambda c: c["detail"],
            )
        )

        network_items = output.get("network", {}).get("permissive_rules", []) + output.get("network", {}).get(
            "hostnetwork_bypass", []
        )
        parts.append("<h3>Network — NetworkPolicy が機能しないパターン</h3>")
        parts.append(
            _render_chain_cards(
                network_items,
                lambda i: (f"実効性のないルール — {i['policy']}" if "policy" in i else f"hostNetwork バイパス — {i['pod']}"),
                lambda i: f"{i['namespace']} / " + (f"NetworkPolicy/{i['policy']}" if "policy" in i else i["pod"]),
                lambda i: i["detail"],
            )
        )

        parts.append("<h3>Image — イメージ脆弱性 × ノード脱出手段</h3>")
        parts.append(
            _render_chain_cards(
                output.get("image", {}).get("chains", []),
                lambda c: f"{c['pod']} — CRITICAL {c['critical']} / HIGH {c['high']}",
                lambda c: f"{c['namespace']} / {c['pod']} (image {c.get('image')})",
                lambda c: c["detail"],
            )
        )

    if bench_record is not None:
        b = bench_record.output
        total = max(b.get("pass", 0) + b.get("fail", 0) + b.get("warn", 0) + b.get("info", 0), 1)
        pass_pct = b.get("pass", 0) / total * 100
        warn_pct = b.get("warn", 0) / total * 100
        fail_pct = b.get("fail", 0) / total * 100
        parts.append(f"<h3>CIS Kubernetes Benchmark (kube-bench) — {b.get('pass',0)} PASS / {b.get('fail',0)} FAIL / {b.get('warn',0)} WARN</h3>")
        parts.append(
            '<div class="k8s-bench-bar">'
            f'<div class="seg pass" style="width:{pass_pct:.1f}%"></div>'
            f'<div class="seg warn" style="width:{warn_pct:.1f}%"></div>'
            f'<div class="seg fail" style="width:{fail_pct:.1f}%"></div>'
            "</div>"
        )
        for f in b.get("fails", []):
            parts.append(f'<div class="k8s-bench-fail"><span class="id">{_esc(f["id"])}</span>{_esc(f["desc"])}</div>')

    parts.append("</div>")
    return "\n".join(parts)
