from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.ai.ollama import OllamaAdapter, OllamaError
from pownforge.core.analysis import AnalysisError, run_analysis
from pownforge.core.models import Evidence, RunRecord
from pownforge.core.settings import Language
from pownforge.evidence.store import EvidenceStore


def _seed_record(store: EvidenceStore) -> RunRecord:
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    record = RunRecord(target="lab", plugin="network", evidence=evidence, output={"raw_stdout": "hi"})
    store.save(record)
    return record


class FakeAdapter:
    def __init__(self, response: str) -> None:
        self._response = response

    def analyze(self, prompt: str) -> str:
        return self._response


class FailingAdapter:
    def analyze(self, prompt: str) -> str:
        raise OllamaError("llm router not found")


def test_run_analysis_persists_summary_and_findings(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)
    response = json.dumps(
        {"summary": "looks fine", "findings": [{"title": "open port", "severity": "low", "detail": "x"}]}
    )

    record, result = run_analysis(store, seeded.run_id, FakeAdapter(response))  # type: ignore[arg-type]

    assert result.parsed is True
    assert record.analysis == "looks fine"
    assert len(record.findings) == 1

    reloaded = store.load(seeded.run_id)
    assert reloaded.analysis == "looks fine"
    assert len(reloaded.findings) == 1


def test_run_analysis_raises_for_unknown_run(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    with pytest.raises(AnalysisError):
        run_analysis(store, "does-not-exist", FakeAdapter("{}"))  # type: ignore[arg-type]


def test_run_analysis_raises_when_llm_unavailable(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)
    with pytest.raises(AnalysisError):
        run_analysis(store, seeded.run_id, FailingAdapter())  # type: ignore[arg-type]


class CapturingAdapter:
    def __init__(self, response: str) -> None:
        self._response = response
        self.seen_prompt: str | None = None

    def analyze(self, prompt: str) -> str:
        self.seen_prompt = prompt
        return self._response


def test_run_analysis_defaults_to_japanese_instruction(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)
    adapter = CapturingAdapter(json.dumps({"summary": "ok", "findings": []}))

    run_analysis(store, seeded.run_id, adapter)  # type: ignore[arg-type]
    assert "Japanese" in adapter.seen_prompt


def test_run_analysis_honors_explicit_english_language(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "runs")
    seeded = _seed_record(store)
    adapter = CapturingAdapter(json.dumps({"summary": "ok", "findings": []}))

    run_analysis(store, seeded.run_id, adapter, language=Language.EN)  # type: ignore[arg-type]
    assert "entirely in English" in adapter.seen_prompt
    assert "Japanese" not in adapter.seen_prompt
