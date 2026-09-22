from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.ai.ollama import OllamaAdapter, OllamaError
from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.core.walkthrough import WalkthroughError, generate_walkthrough, select_runs
from pownforge.evidence.store import EvidenceStore


def _make_record(store: EvidenceStore, target: str, plugin: str, created_at: str, **overrides) -> RunRecord:
    evidence = Evidence(
        command=[plugin, target],
        started_at=created_at,
        finished_at=created_at,
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    defaults = dict(
        target=target,
        plugin=plugin,
        created_at=created_at,
        evidence=evidence,
        output={"raw_stdout": "hi"},
    )
    defaults.update(overrides)
    record = RunRecord(**defaults)
    store.save(record)
    return record


def test_select_runs_by_explicit_ids_preserves_given_order(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = _make_record(store, "lab", "network", "2026-01-01T00:00:00Z")
    b = _make_record(store, "lab", "nuclei", "2026-01-02T00:00:00Z")

    # Deliberately reversed order -- selection must honor it, not re-sort.
    selected = select_runs(store, [b.run_id, a.run_id], None)
    assert [r.run_id for r in selected] == [b.run_id, a.run_id]


def test_select_runs_by_target_sorts_chronologically(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    later = _make_record(store, "lab", "nuclei", "2026-01-02T00:00:00Z")
    earlier = _make_record(store, "lab", "network", "2026-01-01T00:00:00Z")
    _make_record(store, "other-target", "network", "2026-01-01T00:00:00Z")

    selected = select_runs(store, None, "lab")
    assert [r.run_id for r in selected] == [earlier.run_id, later.run_id]


def test_select_runs_requires_exactly_one_of_run_ids_or_target(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(WalkthroughError):
        select_runs(store, None, None)
    with pytest.raises(WalkthroughError):
        select_runs(store, ["abc"], "lab")


def test_select_runs_raises_for_unknown_run_id(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(WalkthroughError):
        select_runs(store, ["no-such-run"], None)


def test_select_runs_raises_when_target_has_no_runs(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    _make_record(store, "lab", "network", "2026-01-01T00:00:00Z")
    with pytest.raises(WalkthroughError):
        select_runs(store, None, "no-such-target")


def test_generate_walkthrough_does_not_modify_any_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = _make_record(
        store, "lab", "network", "2026-01-01T00:00:00Z",
        findings=[Finding(title="Open port 3000", severity="low")],
    )
    b = _make_record(store, "lab", "nuclei", "2026-01-02T00:00:00Z")

    path_a = tmp_path / "runs" / f"{a.run_id}.json"
    path_b = tmp_path / "runs" / f"{b.run_id}.json"
    before_a, before_b = path_a.read_text(), path_b.read_text()

    seen_prompt = {}

    def fake_analyze(self, prompt: str) -> str:
        seen_prompt["prompt"] = prompt
        return "First a network scan found an open port, then nuclei ran but found nothing."

    monkeypatch.setattr(OllamaAdapter, "analyze", fake_analyze)
    adapter = OllamaAdapter()

    walkthrough = generate_walkthrough(store, adapter, [a.run_id, b.run_id], None)

    assert walkthrough.records[0].run_id == a.run_id
    assert "network scan found an open port" in walkthrough.narrative
    assert walkthrough.suggestions == []  # plain-text response -> graceful fallback
    assert "Open port 3000" in seen_prompt["prompt"]
    assert "target=lab plugin=network" in seen_prompt["prompt"]
    assert "target=lab plugin=nuclei" in seen_prompt["prompt"]

    # Read-only: the stored run files must be byte-for-byte unchanged.
    assert path_a.read_text() == before_a
    assert path_b.read_text() == before_b


def test_generate_walkthrough_parses_narrative_and_suggestions_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = _make_record(store, "lab", "web", "2026-01-01T00:00:00Z")

    response = json.dumps(
        {
            "narrative": "We fuzzed the app and found an exposed id parameter.",
            "suggestions": [
                {
                    "title": "Try sqlmap against the id parameter",
                    "plugin": "sqlmap",
                    "rationale": "The id parameter looks unvalidated and untested for injection.",
                },
                {"title": "no plugin here", "plugin": None, "rationale": "generic advice"},
            ],
        }
    )
    monkeypatch.setattr(OllamaAdapter, "analyze", lambda self, prompt: response)

    walkthrough = generate_walkthrough(store, OllamaAdapter(), [a.run_id], None)

    assert walkthrough.narrative == "We fuzzed the app and found an exposed id parameter."
    assert len(walkthrough.suggestions) == 2
    assert walkthrough.suggestions[0].title == "Try sqlmap against the id parameter"
    assert walkthrough.suggestions[0].plugin == "sqlmap"
    assert walkthrough.suggestions[1].plugin is None


def test_generate_walkthrough_skips_suggestions_without_a_title(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = _make_record(store, "lab", "web", "2026-01-01T00:00:00Z")

    response = json.dumps(
        {
            "narrative": "narrative text",
            "suggestions": [{"title": "", "rationale": "no title, should be dropped"}, "not-a-dict"],
        }
    )
    monkeypatch.setattr(OllamaAdapter, "analyze", lambda self, prompt: response)

    walkthrough = generate_walkthrough(store, OllamaAdapter(), [a.run_id], None)
    assert walkthrough.suggestions == []


def test_generate_walkthrough_falls_back_to_plain_text_when_not_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = _make_record(store, "lab", "web", "2026-01-01T00:00:00Z")

    monkeypatch.setattr(
        OllamaAdapter, "analyze", lambda self, prompt: "the model just ignored the JSON instructions"
    )

    walkthrough = generate_walkthrough(store, OllamaAdapter(), [a.run_id], None)
    assert walkthrough.narrative == "the model just ignored the JSON instructions"
    assert walkthrough.suggestions == []


def test_generate_walkthrough_wraps_ollama_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = EvidenceStore(tmp_path / "runs")
    a = _make_record(store, "lab", "network", "2026-01-01T00:00:00Z")

    def fake_analyze(self, prompt: str) -> str:
        raise OllamaError("llm router not found")

    monkeypatch.setattr(OllamaAdapter, "analyze", fake_analyze)
    with pytest.raises(WalkthroughError):
        generate_walkthrough(store, OllamaAdapter(), [a.run_id], None)
