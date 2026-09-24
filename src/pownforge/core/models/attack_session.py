from __future__ import annotations

from pydantic import BaseModel, Field


class AttackSessionStage(BaseModel):
    """One entry in an AttackSession: a reference to an already-recorded
    RunRecord, plus an optional human-written note explaining its role in
    the story (e.g. "Initial foothold via Shellshock"). Never creates or
    modifies the referenced run."""

    run_id: str
    label: str = ""


class AttackSession(BaseModel):
    """A named, human-curated, persisted ordering of already-recorded runs
    (RunRecord ids, from plugin scans or `result import`), used purely to
    organize/visualize an engagement's story across reports/Emacs/Web UI.

    This is a read-only grouping+labeling layer over EvidenceStore: it
    never creates a run, never executes anything, and grants no new
    authorization beyond what each referenced run already went through
    (ScopePolicy via ScanRunner or `result import`). It's the persisted,
    named counterpart to an ad-hoc `pownforge walkthrough generate
    <run-id>...` invocation -- see core/attack_session.py and
    docs/handbook.md §11."""

    name: str
    description: str = ""
    # Purely a cross-reference for readers, e.g. "this session's stages all
    # belong to Engagement X" -- not validated against ScopePolicy, since
    # AttackSessionStore (like EvidenceStore) never needs a policy handle.
    engagement: str | None = None
    stages: list[AttackSessionStage] = Field(default_factory=list)
