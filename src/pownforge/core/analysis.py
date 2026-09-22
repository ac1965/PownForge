from __future__ import annotations

from pownforge.ai.ollama import AnalysisResult, OllamaAdapter, OllamaError, parse_analysis_response
from pownforge.core.models import RunRecord
from pownforge.core.settings import Language, language_instruction
from pownforge.evidence.store import EvidenceStore

_PROMPT_TEMPLATE = (
    "You are assisting a human penetration tester in reviewing raw tool output. "
    "Respond with ONLY a single JSON object (no prose, no markdown code fences) matching "
    'this schema: {{"summary": "<2-4 sentence plain-language summary>", "findings": '
    '[{{"title": "<short title>", "severity": "<one of: info, low, medium, high, critical>", '
    '"detail": "<1-2 sentence explanation>"}}]}}. Only include findings you can support '
    "directly from the raw output below; return an empty findings list if nothing stands "
    "out. Phrase every finding as something worth a human reviewing, never as a confirmed "
    "vulnerability. {language_instruction}\n\n"
    "Target: {target}\nPlugin: {plugin}\n\n"
    "Raw output:\n{raw_stdout}"
)


class AnalysisError(RuntimeError):
    """Raised when a run cannot be analyzed (unknown run_id, or the LLM router failed)."""


def run_analysis(
    store: EvidenceStore,
    run_id: str,
    adapter: OllamaAdapter,
    language: Language = Language.JA,
) -> tuple[RunRecord, AnalysisResult]:
    """Ask the local LLM to summarize/classify a run, then persist the result.

    Shared by the CLI `analyze` command and the web API so the prompt, JSON
    parsing, and persistence live in exactly one place.
    """
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        raise AnalysisError(str(exc)) from exc

    prompt = _PROMPT_TEMPLATE.format(
        target=record.target,
        plugin=record.plugin,
        raw_stdout=record.output.get("raw_stdout", ""),
        language_instruction=language_instruction(language),
    )
    try:
        response = adapter.analyze(prompt)
    except OllamaError as exc:
        raise AnalysisError(str(exc)) from exc

    result = parse_analysis_response(response)
    record.analysis = result.summary
    record.findings = result.findings
    store.save(record)
    return record, result
