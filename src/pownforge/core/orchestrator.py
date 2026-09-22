from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from pownforge.core.models import Playbook, PlaybookStep, RunRecord
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


@dataclass
class PlaybookStepResult:
    step: PlaybookStep
    record: RunRecord | None
    error: str | None


def run_playbook(
    playbook: Playbook,
    target_name: str,
    policy: ScopePolicy,
    registry: PluginRegistry,
    store: EvidenceStore,
    audit: AuditStore | None = None,
    on_step: OnStep | None = None,
) -> list[PlaybookStepResult]:
    """Run every step of PLAYBOOK against TARGET_NAME in order, via the same
    ScanRunner/ScopePolicy path `pownforge scan <plugin>` uses for a single
    manual run -- this grants no execution right beyond what TARGET_NAME's
    own `allowed_plugins` already authorizes for each step's plugin.

    A step that fails (policy rejection, missing tool, plugin/runner error)
    does not stop the playbook: later steps are independent scans of the
    same target, not consumers of the failed step's output, so running them
    anyway surfaces more information than aborting would. Every failure is
    still reported in the returned results (never silently dropped) -- see
    PlaybookStepResult.error."""
    runner = ScanRunner(policy=policy, registry=registry, store=store, audit=audit)
    results: list[PlaybookStepResult] = []
    total = len(playbook.steps)
    for index, step in enumerate(playbook.steps, start=1):
        if on_step is not None:
            on_step(index, total, step)
        try:
            record = runner.run(target_name, step.plugin, step.options)
        except (PolicyError, RunnerError, PluginError) as exc:
            results.append(PlaybookStepResult(step=step, record=None, error=str(exc)))
            continue
        results.append(PlaybookStepResult(step=step, record=record, error=None))
    return results
