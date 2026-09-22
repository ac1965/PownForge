from __future__ import annotations

from pownforge.core.models import (
    AttackSession,
    AttackSessionStage,
    Evidence,
    Finding,
    KillChainPhase,
    RunRecord,
)
from pownforge.reporting.attack_session import render_html, render_markdown


def _record(target: str, plugin: str, created_at: str, **overrides) -> RunRecord:
    evidence_fields = {
        "command": [plugin, target],
        "started_at": created_at,
        "finished_at": created_at,
        "returncode": 0,
        "stdout_sha256": "abc",
        "stderr_sha256": "def",
    }
    evidence_fields.update(overrides.pop("evidence_overrides", {}))
    evidence = Evidence(**evidence_fields)
    defaults = dict(target=target, plugin=plugin, created_at=created_at, evidence=evidence, output={})
    defaults.update(overrides)
    return RunRecord(**defaults)


def test_render_markdown_includes_meta_path_and_stage_labels() -> None:
    session = AttackSession(
        name="op-1",
        description="Test operation",
        engagement="eng1",
        stages=[
            AttackSessionStage(run_id="run-a", label="Initial foothold via Shellshock"),
            AttackSessionStage(run_id="run-b", label="Escalated via SUID binary"),
        ],
    )
    records = [
        _record("lab", "manual", "2026-01-01T00:00:00Z", kill_chain_phase=KillChainPhase.INITIAL_ACCESS),
        _record("lab", "manual", "2026-01-02T00:00:00Z", kill_chain_phase=KillChainPhase.PRIVILEGE_ESCALATION),
    ]
    # Align generated run_ids with the session's stage run_ids for a realistic render.
    records[0].run_id = "run-a"
    records[1].run_id = "run-b"

    output = render_markdown(session, records)

    assert "# Attack Session: op-1" in output
    assert "Test operation" in output
    assert "**Engagement:** `eng1`" in output
    assert "**Stages:** 2" in output
    assert "Initial foothold via Shellshock" in output
    assert "Escalated via SUID binary" in output
    assert "[initial-access]" in output
    assert "## Stage 1: lab / manual" in output
    assert "## Stage 2: lab / manual" in output
    assert "**Kill chain phase:** privilege-escalation" in output


def test_render_markdown_handles_empty_session() -> None:
    session = AttackSession(name="op-empty")
    output = render_markdown(session, [])
    assert "ステージがまだありません" in output


def test_render_markdown_shows_findings_grouped_by_status() -> None:
    session = AttackSession(name="op-1", stages=[AttackSessionStage(run_id="run-a")])
    record = _record(
        "lab",
        "manual",
        "2026-01-01T00:00:00Z",
        findings=[Finding(title="Got shell", status="confirmed", severity="critical")],
    )
    record.run_id = "run-a"

    output = render_markdown(session, [record])
    assert "#### 確認済み" in output
    assert "Got shell" in output


def test_render_html_is_self_contained_and_escapes_fields() -> None:
    session = AttackSession(name="op-1", stages=[AttackSessionStage(run_id="run-a", label="<script>evil()</script>")])
    record = _record("<script>alert(1)</script>", "manual", "2026-01-01T00:00:00Z")
    record.run_id = "run-a"

    output = render_html(session, [record])
    assert output.startswith("<!doctype html>")
    assert "<script>evil()</script>" not in output
    assert "&lt;script&gt;evil()&lt;/script&gt;" in output
    assert "<script>alert(1)</script>" not in output


def test_render_html_shows_kill_chain_phase_and_via_target() -> None:
    session = AttackSession(name="op-1", stages=[AttackSessionStage(run_id="run-a")])
    record = _record(
        "internal-db",
        "manual",
        "2026-01-01T00:00:00Z",
        kill_chain_phase=KillChainPhase.LATERAL_MOVEMENT,
        via_target="jump-host",
        engagement="eng1",
    )
    record.run_id = "run-a"

    output = render_html(session, [record])
    assert "<dt>Kill chain phase</dt><dd>lateral-movement</dd>" in output
    assert "<dt>Reached via</dt><dd>jump-host (engagement: eng1)</dd>" in output
