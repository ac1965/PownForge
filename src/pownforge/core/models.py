from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TargetKind(str, Enum):
    HOST = "host"
    URL = "url"


class Target(BaseModel):
    name: str
    kind: TargetKind
    address: str
    allowed_plugins: list[str] = Field(default_factory=list)
    notes: str | None = None


class PluginMeta(BaseModel):
    name: str
    version: str
    description: str


class Evidence(BaseModel):
    command: list[str]
    started_at: datetime
    finished_at: datetime
    returncode: int
    stdout_sha256: str
    stderr_sha256: str


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
    # "ai": produced by `pownforge analyze` from unverified LLM output — never
    # a confirmed vulnerability. "manual": entered/reviewed by a human.
    source: str = "manual"
    # Every finding starts unverified, regardless of source: a tool (or an
    # LLM) saying "vulnerable" is a candidate, not a confirmed result. Only a
    # human review (`pownforge result review`) moves it to confirmed or
    # false-positive.
    status: FindingStatus = FindingStatus.NEEDS_REVIEW


class RunRecord(BaseModel):
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    plugin: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Evidence
    output: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    analysis: str | None = None
