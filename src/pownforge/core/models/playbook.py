from __future__ import annotations

from pydantic import BaseModel, Field

from pownforge.core.models.finding import Severity


class PlaybookStepCondition(BaseModel):
    """Gates a PlaybookStep on whether an earlier step in the same Playbook
    produced a Finding at or above MIN_SEVERITY. Evaluated purely
    deterministically against already-stored Finding.severity values --
    never by an LLM at run time, and never by inspecting a plugin's raw
    output (which has a different shape per plugin) -- see
    core/orchestrator.py."""

    after_step: int
    min_severity: Severity


class PlaybookStep(BaseModel):
    plugin: str
    options: dict[str, str] = Field(default_factory=dict)
    when: PlaybookStepCondition | None = None


class Playbook(BaseModel):
    """A human-authored, version-controlled sequence of plugin runs against
    one target -- `pownforge playbook run <name> --target <t>` executes each
    step in order via the same ScanRunner/ScopePolicy path a manual
    `pownforge scan <plugin>` would use. A step's `when` (see
    PlaybookStepCondition) may skip it based on an earlier step's findings,
    but that condition is fixed at Playbook-authoring time -- what plugin
    runs when is always decided by whoever wrote the Playbook file, never by
    an LLM at run time -- see core/orchestrator.py and docs/handbook.md §8."""

    name: str
    description: str = ""
    steps: list[PlaybookStep] = Field(default_factory=list)
