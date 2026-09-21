from __future__ import annotations

import json

from pownforge.ai.ollama import parse_analysis_response
from pownforge.core.models import Severity


def test_parses_well_formed_json_response() -> None:
    response = json.dumps(
        {
            "summary": "Only one open port, nothing alarming.",
            "findings": [
                {"title": "Open port 3000", "severity": "medium", "detail": "Dev server exposed"}
            ],
        }
    )
    result = parse_analysis_response(response)
    assert result.parsed is True
    assert result.summary == "Only one open port, nothing alarming."
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.MEDIUM
    assert result.findings[0].source == "ai"


def test_extracts_json_wrapped_in_code_fence() -> None:
    response = "Here you go:\n```json\n" + json.dumps({"summary": "ok", "findings": []}) + "\n```"
    result = parse_analysis_response(response)
    assert result.parsed is True
    assert result.summary == "ok"
    assert result.findings == []


def test_falls_back_to_raw_text_when_not_json() -> None:
    response = "The model just wrote a paragraph instead of JSON."
    result = parse_analysis_response(response)
    assert result.parsed is False
    assert result.summary == response
    assert result.findings == []


def test_invalid_severity_downgrades_to_info_but_keeps_finding() -> None:
    response = json.dumps(
        {
            "summary": "ok",
            "findings": [{"title": "Weird one", "severity": "extremely-bad", "detail": "x"}],
        }
    )
    result = parse_analysis_response(response)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].title == "Weird one"


def test_skips_findings_without_title() -> None:
    response = json.dumps({"summary": "ok", "findings": [{"severity": "high", "detail": "no title"}]})
    result = parse_analysis_response(response)
    assert result.findings == []
