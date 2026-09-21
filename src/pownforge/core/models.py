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


class Finding(BaseModel):
    title: str
    severity: str = "info"
    detail: str = ""


class RunRecord(BaseModel):
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    plugin: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Evidence
    output: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    analysis: str | None = None
