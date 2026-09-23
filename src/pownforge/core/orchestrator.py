from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.models import Playbook, PlaybookStep, PlaybookStepCondition, RunRecord, Severity
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import PluginError

OnStep = Callable[[int, int, PlaybookStep], None]


class PlaybookError(RuntimeError):
    """Raised when a playbook file can't be found or parsed."""


def load_playbook(path: Path) -> Playbook:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except OSError as exc:
        raise PlaybookError(f"could not read playbook file '{path}': {exc}") from exc
    try:
        return Playbook(**data)
    except Exception as exc:  # pydantic ValidationError, etc.
        raise PlaybookError(f"invalid playbook file '{path}': {exc}") from exc


def list_playbooks(playbooks_dir: Path) -> list[Playbook]:
    if not playbooks_dir.is_dir():
        return []
    playbooks = [load_playbook(path) for path in sorted(playbooks_dir.glob("*.yaml"))]
    return sorted(playbooks, key=lambda p: p.name)


def resolve_playbook(playbooks_dir: Path, name: str) -> Playbook:
    path = playbooks_dir / f"{name}.yaml"
    if not path.exists():
        raise PlaybookError(f"no playbook named '{name}' in {playbooks_dir}")
    return load_playbook(path)


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class PlaybookStepResult:
    step: PlaybookStep
    record: RunRecord | None
    error: str | None
    skipped: bool = False


def _validate_steps(steps: list[PlaybookStep]) -> None:
    for index, step in enumerate(steps, start=1):
        if step.when is None:
            continue
        if not (1 <= step.when.after_step < index):
            raise PlaybookError(
                f"step {index} ({step.plugin}): when.after_step={step.when.after_step} "
                f"must refer to an earlier step in this playbook (1..{index - 1})"
            )


def _condition_met(condition: PlaybookStepCondition, results: list[PlaybookStepResult]) -> bool:
    # after_step is 1-indexed and _validate_steps() already guarantees it
    # refers to an earlier, already-executed step.
    gate = results[condition.after_step - 1]
    if gate.record is None:
        return False
    threshold = _SEVERITY_RANK[condition.min_severity]
    return any(_SEVERITY_RANK[finding.severity] >= threshold for finding in gate.record.findings)


def run_playbook(
    playbook: Playbook,
    target_name: str,
    policy: ScopePolicy,
    registry: PluginRegistry,
    store: EvidenceStore,
    audit: AuditStore | None = None,
    on_step: OnStep | None = None,
    concurrency: ConcurrencyGuard | None = None,
) -> list[PlaybookStepResult]:
    """Run every step of PLAYBOOK against TARGET_NAME in order, via the same
    ScanRunner/ScopePolicy path `pownforge scan <plugin>` uses for a single
    manual run -- this grants no execution right beyond what TARGET_NAME's
    own `allowed_plugins` already authorizes for each step's plugin.

    A step whose `when` condition isn't met (see PlaybookStepCondition) is
    skipped -- recorded as such, never silently dropped. This is the only
    form of branching a Playbook supports: the condition and its threshold
    are fixed when the Playbook file was written, and evaluating it here
    only compares stored Finding.severity values -- no LLM or other runtime
    judgment call decides whether a step runs.

    A step that fails (policy rejection, missing tool, plugin/runner error)
    does not stop the playbook: later steps are independent scans of the
    same target, not consumers of the failed step's output, so running them
    anyway surfaces more information than aborting would. Every failure is
    still reported in the returned results (never silently dropped) -- see
    PlaybookStepResult.error."""
    _validate_steps(playbook.steps)
    runner = ScanRunner(policy=policy, registry=registry, store=store, audit=audit, concurrency=concurrency)
    results: list[PlaybookStepResult] = []
    total = len(playbook.steps)
    for index, step in enumerate(playbook.steps, start=1):
        if on_step is not None:
            on_step(index, total, step)
        if step.when is not None and not _condition_met(step.when, results):
            results.append(PlaybookStepResult(step=step, record=None, error=None, skipped=True))
            continue
        try:
            record = runner.run(target_name, step.plugin, step.options)
        except (PolicyError, RunnerError, PluginError) as exc:
            results.append(PlaybookStepResult(step=step, record=None, error=str(exc)))
            continue
        results.append(PlaybookStepResult(step=step, record=record, error=None))
    return results
