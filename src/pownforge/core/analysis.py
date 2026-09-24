from __future__ import annotations

from pownforge.ai.ollama import AnalysisResult, LLMAdapter, LLMError, parse_analysis_response
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
    "vulnerability. {language_instruction}\n"
    "{checklist_section}\n"
    "Target: {target}\nPlugin: {plugin}\n\n"
    "Raw output:\n{raw_stdout}"
)

# Plugins whose raw output is a web application response/probe, where an
# OWASP-style checklist gives the LLM a concrete list of categories to weigh
# the output against -- it never widens what counts as evidence, just names
# the kinds of issues worth checking for. See docs/handbook.md #10.
_WEB_PLUGINS = frozenset({"web", "nuclei", "sqlmap"})

_OWASP_CHECKLIST = (
    "\nWhen reviewing web-application output, weigh it against these OWASP "
    "Top 10-style categories -- report a finding only when the raw output "
    "below actually evidences it, never speculatively:\n"
    "- Broken Access Control (missing authorization checks, IDOR-style object references)\n"
    "- Cryptographic Failures (cleartext transport, weak/expired TLS)\n"
    "- Injection (SQL, command, template, or reflected/stored XSS in a response)\n"
    "- Insecure Design (no rate limiting, predictable resource identifiers)\n"
    "- Security Misconfiguration (verbose stack traces, default credentials, exposed admin/debug endpoints)\n"
    "- Vulnerable and Outdated Components (server/framework banners naming a known-old version)\n"
    "- Identification and Authentication Failures (weak session handling, no lockout on repeated attempts)\n"
    "- Software and Data Integrity Failures (unsigned update or deserialization paths)\n"
    "- Security Logging and Monitoring Failures (behavior implying errors go unlogged/unmonitored)\n"
    "- Server-Side Request Forgery (an endpoint that fetches an attacker-supplied URL)\n"
)


class AnalysisError(RuntimeError):
    """Raised when a run cannot be analyzed (unknown run_id, or the LLM router failed)."""


def run_analysis(
    store: EvidenceStore,
    run_id: str,
    adapter: LLMAdapter,
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
        checklist_section=_OWASP_CHECKLIST if record.plugin in _WEB_PLUGINS else "",
    )
    try:
        response = adapter.analyze(prompt)
    except LLMError as exc:
        raise AnalysisError(str(exc)) from exc

    result = parse_analysis_response(response)
    record.analysis = result.summary
    record.findings = result.findings
    store.save(record)
    return record, result
