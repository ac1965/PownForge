from __future__ import annotations

import html as html_escape

from pownforge.core.models import Finding, FindingStatus, RunRecord, Severity
from pownforge.core.operation import Action, ActionStatus, AttackOperation, find_approval

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_STATUS_SECTIONS = [
    (FindingStatus.CONFIRMED, "確認済み"),
    (FindingStatus.NEEDS_REVIEW, "要確認"),
    (FindingStatus.FALSE_POSITIVE, "誤検知として却下"),
]

_SOURCE_LABELS = {"ai": "AI推定", "tool": "ツール検出"}


def _sorted_findings(record: RunRecord, status: FindingStatus) -> list[Finding]:
    return sorted(
        (f for f in record.findings if f.status == status),
        key=lambda f: _SEVERITY_ORDER[f.severity],
    )


def _approved_by(operation: AttackOperation, action: Action) -> str | None:
    if action.status not in (ActionStatus.APPROVED, ActionStatus.COMPLETED):
        return None
    try:
        return find_approval(operation, action.id).approved_by
    except Exception:  # noqa: BLE001 - find_approval raises OperationError; report is read-only
        return None


def render_markdown(operation: AttackOperation, records: dict[str, RunRecord]) -> str:
    """Render OPERATION as Markdown. RECORDS maps an Action's `run_id` to
    its resolved RunRecord, for every action that has already been
    executed (`operation.actions[i].run_id` is not None) -- this function
    never loads anything itself, matching reporting/attack_session.py's
    split between data loading (core/) and rendering (reporting/). A
    purely read-only view: it never executes anything and never mutates
    OPERATION."""
    lines = [f"# Attack Operation: {operation.name}", ""]
    if operation.objective:
        lines.append(operation.objective)
        lines.append("")
    if operation.engagement:
        lines.append(f"- **Engagement:** `{operation.engagement}`")
    lines += [
        f"- **Nodes:** {len(operation.nodes)}",
        f"- **Edges:** {len(operation.edges)}",
        f"- **Actions:** {len(operation.actions)}",
        f"- **Approvals:** {len(operation.approvals)}",
        "",
    ]

    lines.append("## グラフ")
    lines.append("")
    lines.append("### ノード")
    lines.append("")
    if not operation.nodes:
        lines.append("_ノードがまだありません。_")
    for node in operation.nodes:
        label = f" — {node.label}" if node.label else ""
        techniques = f" [{', '.join(node.attack_technique_ids)}]" if node.attack_technique_ids else ""
        lines.append(f"- `{node.id}` ({node.target}, {node.state.value}){label}{techniques}")
    lines.append("")

    lines.append("### エッジ")
    lines.append("")
    if not operation.edges:
        lines.append("_エッジがまだありません。_")
    for edge in operation.edges:
        caps = ", ".join(c.value for c in edge.capabilities)
        techniques = f" [{', '.join(edge.attack_technique_ids)}]" if edge.attack_technique_ids else ""
        lines.append(f"- `{edge.source}` → `{edge.destination}` ({edge.relationship}, {caps}){techniques}")
    lines.append("")

    lines.append("## Actions")
    lines.append("")
    if not operation.actions:
        lines.append("_Actionがまだありません。_")
    for action in operation.actions:
        techniques = f" [{', '.join(action.attack_technique_ids)}]" if action.attack_technique_ids else ""
        lines += [
            f"### {action.id}: {action.name}{techniques}",
            "",
            f"- **Phase:** {action.phase.value}",
            f"- **Kind:** {action.kind.value}",
            f"- **Target:** {action.target}",
            f"- **Status:** {action.status.value}",
        ]
        if action.plugin:
            lines.append(f"- **Plugin:** {action.plugin}")
        approved_by = _approved_by(operation, action)
        if approved_by:
            lines.append(f"- **Approved by:** {approved_by}")
        if action.requires:
            lines.append(f"- **Requires:** {', '.join(action.requires)}")
        if action.provides:
            lines.append(f"- **Provides:** {', '.join(action.provides)}")

        record = records.get(action.run_id) if action.run_id else None
        if record is None:
            lines += ["", "_未実行(まだ`operation execute`を通していません)。_", ""]
            continue

        lines += [
            f"- **Run id:** {record.run_id}",
            f"- **Command:** `{' '.join(record.evidence.command)}`",
            "",
            "#### Findings",
        ]
        if record.findings:
            for status, heading in _STATUS_SECTIONS:
                findings = _sorted_findings(record, status)
                if not findings:
                    continue
                lines += ["", f"##### {heading}", ""]
                for finding in findings:
                    tag = _SOURCE_LABELS.get(finding.source, "manual")
                    lines.append(
                        f"- **[{finding.severity.value}]** ({tag}, `{finding.finding_id}`) "
                        f"{finding.title} — {finding.detail}"
                    )
        else:
            lines += ["", "_このActionにはfindingが記録されていません。_"]
        lines.append("")

    return "\n".join(lines)


_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; }
h3 { font-size: 1rem; }
h4 { font-size: .95rem; margin-bottom: .25rem; }
ul.graph li { margin-bottom: .3rem; }
dl { display: grid; grid-template-columns: 9rem 1fr; gap: .25rem .75rem; margin: 0; }
dt { font-weight: bold; }
dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
.finding { margin: 0 0 .75rem 0; }
.badge { display: inline-block; font-size: .75rem; font-weight: bold; padding: .1rem .4rem;
         border-radius: 4px; margin-right: .4rem; text-transform: uppercase; color: white; }
.severity-critical .badge { background: #c0392b; }
.severity-high .badge { background: #e67e22; }
.severity-medium .badge { background: #f1c40f; color: black; }
.severity-low .badge { background: #3498db; }
.severity-info .badge { background: #95a5a6; }
.source { font-size: .75rem; opacity: .7; margin-right: .4rem; }
.technique { font-size: .75rem; font-weight: normal; opacity: .7; }
.not-run { font-style: italic; color: #777; }
"""


def _esc(value: object) -> str:
    return html_escape.escape(str(value))


def render_html(operation: AttackOperation, records: dict[str, RunRecord]) -> str:
    parts = [
        "<!doctype html>",
        '<html lang="ja">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Attack Operation: {_esc(operation.name)} — PownForge report</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>Attack Operation: {_esc(operation.name)}</h1>",
    ]
    if operation.objective:
        parts.append(f"<p>{_esc(operation.objective)}</p>")
    parts.append("<dl>")
    if operation.engagement:
        parts.append(f"<dt>Engagement</dt><dd>{_esc(operation.engagement)}</dd>")
    parts.append(f"<dt>Nodes</dt><dd>{len(operation.nodes)}</dd>")
    parts.append(f"<dt>Edges</dt><dd>{len(operation.edges)}</dd>")
    parts.append(f"<dt>Actions</dt><dd>{len(operation.actions)}</dd>")
    parts.append(f"<dt>Approvals</dt><dd>{len(operation.approvals)}</dd>")
    parts.append("</dl>")

    parts.append("<h2>グラフ</h2>")
    parts.append("<h3>ノード</h3>")
    if not operation.nodes:
        parts.append("<p><em>ノードがまだありません。</em></p>")
    else:
        parts.append("<ul class='graph'>")
        for node in operation.nodes:
            label = f" — {_esc(node.label)}" if node.label else ""
            techniques = (
                f' <span class="technique">[{_esc(", ".join(node.attack_technique_ids))}]</span>'
                if node.attack_technique_ids
                else ""
            )
            parts.append(
                f"<li><code>{_esc(node.id)}</code> ({_esc(node.target)}, {_esc(node.state.value)}){label}{techniques}</li>"
            )
        parts.append("</ul>")

    parts.append("<h3>エッジ</h3>")
    if not operation.edges:
        parts.append("<p><em>エッジがまだありません。</em></p>")
    else:
        parts.append("<ul class='graph'>")
        for edge in operation.edges:
            caps = ", ".join(c.value for c in edge.capabilities)
            techniques = (
                f' <span class="technique">[{_esc(", ".join(edge.attack_technique_ids))}]</span>'
                if edge.attack_technique_ids
                else ""
            )
            parts.append(
                f"<li><code>{_esc(edge.source)}</code> → <code>{_esc(edge.destination)}</code> "
                f"({_esc(edge.relationship)}, {_esc(caps)}){techniques}</li>"
            )
        parts.append("</ul>")

    parts.append("<h2>Actions</h2>")
    if not operation.actions:
        parts.append("<p><em>Actionがまだありません。</em></p>")
    for action in operation.actions:
        techniques = (
            f' <span class="technique">[{_esc(", ".join(action.attack_technique_ids))}]</span>'
            if action.attack_technique_ids
            else ""
        )
        parts.append(f"<h3><code>{_esc(action.id)}</code>: {_esc(action.name)}{techniques}</h3>")
        rows = [
            ("Phase", action.phase.value),
            ("Kind", action.kind.value),
            ("Target", action.target),
            ("Status", action.status.value),
        ]
        if action.plugin:
            rows.append(("Plugin", action.plugin))
        approved_by = _approved_by(operation, action)
        if approved_by:
            rows.append(("Approved by", approved_by))
        if action.requires:
            rows.append(("Requires", ", ".join(action.requires)))
        if action.provides:
            rows.append(("Provides", ", ".join(action.provides)))
        parts.append("<dl>")
        for key, value in rows:
            parts.append(f"<dt>{_esc(key)}</dt><dd>{_esc(value)}</dd>")
        parts.append("</dl>")

        record = records.get(action.run_id) if action.run_id else None
        if record is None:
            parts.append('<p class="not-run">未実行(まだ operation execute を通していません)。</p>')
            continue

        parts += [
            "<dl>",
            f"<dt>Run id</dt><dd>{_esc(record.run_id)}</dd>",
            f"<dt>Command</dt><dd>{_esc(' '.join(record.evidence.command))}</dd>",
            "</dl>",
            "<h4>Findings</h4>",
        ]
        if record.findings:
            for status, heading in _STATUS_SECTIONS:
                findings = _sorted_findings(record, status)
                if not findings:
                    continue
                parts.append(f"<h5>{_esc(heading)}</h5>")
                for finding in findings:
                    tag = _SOURCE_LABELS.get(finding.source, "manual")
                    parts.append(
                        f'<div class="finding severity-{finding.severity.value}">'
                        f'<span class="badge">{_esc(finding.severity.value)}</span>'
                        f'<span class="source">({_esc(tag)}, <code>{_esc(finding.finding_id)}</code>)</span>'
                        f"<strong>{_esc(finding.title)}</strong> — {_esc(finding.detail)}"
                        f"</div>"
                    )
        else:
            parts.append("<p><em>このActionにはfindingが記録されていません。</em></p>")

    parts += ["</body>", "</html>"]
    return "\n".join(parts)
