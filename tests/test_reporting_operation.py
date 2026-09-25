from __future__ import annotations

from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.core.operation import (
    Action,
    ActionKind,
    ActionStatus,
    Approval,
    AttackEdge,
    AttackNode,
    AttackOperation,
)
from pownforge.reporting.operation import render_html, render_markdown


def _record(run_id: str, target: str, plugin: str, **overrides) -> RunRecord:
    evidence_fields = {
        "command": [plugin, target],
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "returncode": 0,
        "stdout_sha256": "abc",
        "stderr_sha256": "def",
    }
    evidence_fields.update(overrides.pop("evidence_overrides", {}))
    defaults = dict(target=target, plugin=plugin, evidence=Evidence(**evidence_fields), output={})
    defaults.update(overrides)
    record = RunRecord(**defaults)
    record.run_id = run_id
    return record


def test_render_markdown_shows_graph_and_untagged_action() -> None:
    operation = AttackOperation(
        name="op-1",
        objective="lab engagement",
        engagement="eng1",
        nodes=[AttackNode(id="n-a", target="a", label="foothold", attack_technique_ids=["T1595"])],
        edges=[AttackEdge(source="a", destination="b", attack_technique_ids=["T1210"])],
        actions=[
            Action(
                id="a1", name="recon scan", phase="discovery", kind=ActionKind.SCAN, target="a",
                plugin="network", attack_technique_ids=["T1190"],
            )
        ],
    )

    output = render_markdown(operation, {})

    assert "# Attack Operation: op-1" in output
    assert "lab engagement" in output
    assert "**Engagement:** `eng1`" in output
    assert "`n-a` (a, known) — foothold [T1595]" in output
    assert "`a` → `b`" in output and "[T1210]" in output
    assert "### a1: recon scan [T1190]" in output
    assert "未実行" in output


def test_render_markdown_shows_findings_for_completed_action() -> None:
    action = Action(
        id="a1", name="recon scan", phase="discovery", kind=ActionKind.SCAN, target="a",
        plugin="network", status=ActionStatus.COMPLETED, run_id="run-a",
    )
    operation = AttackOperation(
        name="op-1",
        nodes=[AttackNode(id="n-a", target="a")],
        actions=[action],
        approvals=[Approval(id="ap1", action_id="a1", approved_by="operator")],
    )
    record = _record("run-a", "a", "network", findings=[Finding(title="Open port", status="confirmed", severity="high")])

    output = render_markdown(operation, {"run-a": record})

    assert "**Approved by:** operator" in output
    assert "**Run id:** run-a" in output
    assert "#### 確認済み" in output
    assert "Open port" in output


def test_render_markdown_handles_empty_operation() -> None:
    output = render_markdown(AttackOperation(name="empty"), {})
    assert "ノードがまだありません" in output
    assert "エッジがまだありません" in output
    assert "Actionがまだありません" in output


def test_render_html_is_self_contained_and_escapes_fields() -> None:
    operation = AttackOperation(
        name="op-1",
        nodes=[AttackNode(id="n-a", target="<script>evil()</script>")],
    )
    output = render_html(operation, {})
    assert output.startswith("<!doctype html>")
    assert "<script>evil()</script>" not in output
    assert "&lt;script&gt;evil()&lt;/script&gt;" in output


def test_render_html_shows_technique_tags_and_not_run_marker() -> None:
    action = Action(
        id="a1", name="pivot", phase="lateral-movement", kind=ActionKind.PIVOT, target="b",
        attack_technique_ids=["T1210"],
    )
    operation = AttackOperation(name="op-1", actions=[action])

    output = render_html(operation, {})

    assert "[T1210]" in output
    assert "未実行" in output
