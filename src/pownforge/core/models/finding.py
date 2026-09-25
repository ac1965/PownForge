from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    NEEDS_REVIEW = "needs-review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false-positive"


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str
    severity: Severity = Severity.INFO
    detail: str = ""
    # "ai": produced by `pownforge analyze` from unverified LLM output.
    # "tool": produced by a plugin's own tool-native detection (e.g. a nuclei
    # template match), via the "_findings" convention in Plugin.normalize().
    # "manual": entered/reviewed by a human. None of these is ever a
    # confirmed vulnerability by itself — see FindingStatus.
    source: str = "manual"
    # Every finding starts unverified, regardless of source: a tool (or an
    # LLM) saying "vulnerable" is a candidate, not a confirmed result. Only a
    # human review (`pownforge result review`) moves it to confirmed or
    # false-positive.
    status: FindingStatus = FindingStatus.NEEDS_REVIEW
    # MITRE ATT&CK for Enterprise technique ids (e.g. "T1190"), assigned
    # explicitly by a plugin's normalize() or a human reviewer -- never
    # inferred/scored here. Optional and additive: default empty list keeps
    # existing findings (no tags) loading unchanged. See docs/handbook.md
    # §14 "ATT&CKタグ" for the adopted vocabulary and assignment criteria.
    attack_technique_ids: list[str] = Field(default_factory=list)

    @field_validator("attack_technique_ids")
    @classmethod
    def _drop_blank_technique_ids(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item and item.strip()]


class Suggestion(BaseModel):
    """An AI-generated "what to try next" recommendation produced by
    `pownforge walkthrough generate` (core/walkthrough.py). Deliberately not
    a Finding: it isn't a vulnerability candidate to confirm/reject, has no
    status/review workflow, and is never persisted (a walkthrough never
    writes to any RunRecord). It carries no execution authority either —
    running the suggested plugin still requires a human to explicitly call
    `pownforge scan <plugin>`."""

    suggestion_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    title: str
    plugin: str | None = None
    rationale: str = ""
