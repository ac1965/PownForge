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
    # Common severity model (refactor v3 §3): `severity` above stays the
    # single authoritative 5-level bucket every existing consumer (reports,
    # walkthroughs, filtering, RunRecord persistence) already sorts/groups
    # by -- these three fields are purely additive context, never a
    # replacement. `cvss_score`/`cvss_vector` carry a numeric CVSS base
    # score/vector when the plugin's own tool provides one (e.g. trivy's
    # `CVSS.nvd.V3Score`, grype's `vulnerability.cvss[].metrics.baseScore`);
    # `native_severity` keeps the tool's own severity label exactly as it
    # reported it, before coerce_finding() (core/finding_utils.py) mapped
    # it onto `severity` -- e.g. grype's "Negligible" or trivy's "UNKNOWN".
    # All three are None when the source tool has no CVSS data (config/
    # secret findings, most non-CVE findings) or a plugin hasn't been
    # updated to populate them; existing findings without these fields
    # load unchanged. See docs/handbook.md §3.5 "共通severityモデル".
    cvss_score: float | None = None
    cvss_vector: str | None = None
    native_severity: str | None = None

    @field_validator("attack_technique_ids")
    @classmethod
    def _drop_blank_technique_ids(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item and item.strip()]

    @field_validator("cvss_score")
    @classmethod
    def _validate_cvss_score_range(cls, value: float | None) -> float | None:
        if value is not None and not (0.0 <= value <= 10.0):
            return None
        return value


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
