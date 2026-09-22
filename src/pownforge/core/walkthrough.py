from __future__ import annotations

import json
from dataclasses import dataclass, field

from pownforge.ai.ollama import OllamaAdapter, OllamaError
from pownforge.core.models import RunRecord, Suggestion
from pownforge.core.settings import Language, language_instruction
from pownforge.evidence.store import EvidenceStore

_PROMPT_TEMPLATE = (
    "You are assisting a human penetration tester in writing up a walkthrough "
    "of a multi-step engagement, from the structured facts of each step below "
    "(no raw tool output).\n\n"
    "Respond with ONLY a single JSON object (no prose outside it, no markdown "
    "code fences) matching this schema:\n"
    "{{\"narrative\": \"<connective prose describing how the engagement "
    "unfolded from one run to the next -- what was tried, what came out of "
    "it, and why the next step followed>\", \"suggestions\": "
    "[{{\"title\": \"<short actionable next step>\", \"plugin\": \"<a plugin "
    "name this suggests trying next, or null if not tool-specific>\", "
    "\"rationale\": \"<1-2 sentence reason, citing the specific findings/steps "
    "that motivate it>\"}}]}}\n\n"
    "Do not invent facts not present below. Never assert a finding as a "
    "confirmed vulnerability unless its status is explicitly \"confirmed\"; "
    "findings with status \"needs-review\" must be described as unverified/"
    "unconfirmed, and \"false-positive\" findings should be described as "
    "ruled out. Only include a suggestion when it is concretely motivated by "
    "the steps below; return an empty suggestions list if nothing stands out. "
    "A suggestion is advice for a human to consider, never something you can "
    "act on yourself. {language_instruction}\n\n"
    "Steps, in order:\n{steps}"
)


class WalkthroughError(RuntimeError):
    """Raised when a walkthrough's runs can't be selected or narrated."""


@dataclass
class Walkthrough:
    records: list[RunRecord]
    narrative: str
    suggestions: list[Suggestion] = field(default_factory=list)


def select_runs(
    store: EvidenceStore,
    run_ids: list[str] | None,
    target: str | None,
    targets: list[str] | None = None,
) -> list[RunRecord]:
    """Select the runs a walkthrough should cover, in narrative order.

    Exactly one of RUN_IDS/TARGET/TARGETS must be given. RUN_IDS are loaded
    in the order given (the caller's chosen narrative order); TARGET
    selects every run recorded against that single target name, oldest
    first (the order they actually happened in); TARGETS generalizes that
    to several target names at once (e.g. every member of an Engagement),
    still oldest first across all of them together -- this is how a
    walkthrough can span a lateral-movement chain (`pownforge walkthrough
    generate --engagement <name>`, see core/policy.py::
    ScopePolicy.authorize_pivot()). Never mutates or re-saves any run."""
    given = [bool(run_ids), bool(target), bool(targets)]
    if sum(given) > 1:
        raise WalkthroughError("give exactly one of: run ids, --target, or --engagement")
    if not any(given):
        raise WalkthroughError("give at least one run id, --target <name>, or --engagement <name>")

    if run_ids:
        records: list[RunRecord] = []
        for run_id in run_ids:
            try:
                records.append(store.load(run_id))
            except FileNotFoundError as exc:
                raise WalkthroughError(str(exc)) from exc
        return records

    wanted = {target} if target else set(targets or [])
    records = sorted(
        (r for r in store.list() if r.target in wanted),
        key=lambda r: r.created_at,
    )
    if not records:
        label = f"target '{target}'" if target else f"engagement targets {sorted(wanted)}"
        raise WalkthroughError(f"no runs recorded against {label}")
    return records


def _describe_run(index: int, record: RunRecord) -> str:
    header = f"{index}. target={record.target} plugin={record.plugin} at={record.created_at.isoformat()}"
    if record.via_target:
        header += f" (reached via target={record.via_target}, engagement={record.engagement})"
    lines = [header]
    if not record.findings:
        lines.append("   (no findings)")
    for finding in record.findings:
        lines.append(
            f"   - [{finding.severity.value}/{finding.status.value}] {finding.title}: {finding.detail}"
        )
    return "\n".join(lines)


def _extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in response")
    return text[start : end + 1]


def _parse_response(text: str) -> tuple[str, list[Suggestion]]:
    """Parse the `{"narrative": ..., "suggestions": [...]}` JSON the prompt
    asks for. Falls back to treating the whole response as the narrative
    (with no suggestions) when the model didn't return valid JSON -- some
    local models ignore formatting instructions, and that shouldn't crash
    the command or silently discard the narrative. Mirrors
    ai/ollama.py::parse_analysis_response's same degrade-gracefully shape."""
    try:
        payload = json.loads(_extract_json_object(text))
    except ValueError:
        return text.strip(), []

    narrative = str(payload.get("narrative") or "").strip() or text.strip()
    suggestions: list[Suggestion] = []
    for item in payload.get("suggestions") or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        plugin = item.get("plugin")
        suggestions.append(
            Suggestion(
                title=title,
                plugin=str(plugin).strip() or None if plugin else None,
                rationale=str(item.get("rationale") or "").strip(),
            )
        )
    return narrative, suggestions


def generate_walkthrough(
    store: EvidenceStore,
    adapter: OllamaAdapter,
    run_ids: list[str] | None,
    target: str | None,
    language: Language = Language.JA,
    targets: list[str] | None = None,
) -> Walkthrough:
    """Select runs (see select_runs) and ask the local LLM for connective
    narrative prose plus "what to try next" suggestions covering them.
    Read-only: no RunRecord is modified or re-saved, unlike
    core/analysis.py::run_analysis (which overwrites a single run's
    findings) -- a walkthrough is a new, separate artifact. Suggestions are
    advisory only (see Suggestion) and carry no execution authority: a
    human must still explicitly run `pownforge scan <plugin>`."""
    records = select_runs(store, run_ids, target, targets)
    steps = "\n".join(_describe_run(i, r) for i, r in enumerate(records, start=1))
    prompt = _PROMPT_TEMPLATE.format(steps=steps, language_instruction=language_instruction(language))
    try:
        response = adapter.analyze(prompt)
    except OllamaError as exc:
        raise WalkthroughError(str(exc)) from exc
    narrative, suggestions = _parse_response(response)
    return Walkthrough(records=records, narrative=narrative, suggestions=suggestions)
