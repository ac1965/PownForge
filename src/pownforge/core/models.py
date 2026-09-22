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
    # Best-effort output of the plugin's version_command() (e.g. "Nmap
    # version 7.991 ( https://nmap.org )"), captured at scan time so a
    # finding's absence/presence can later be checked against which tool
    # version actually ran. None when the plugin doesn't report a version
    # command, the tool is missing, or the version query itself failed.
    tool_version: str | None = None


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


class RunRecord(BaseModel):
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    plugin: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Evidence
    output: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    analysis: str | None = None


class PolicyViolation(BaseModel):
    """A scan attempt that ScopePolicy.authorize() rejected. No Evidence
    exists for these (no command ever ran), so they're tracked separately
    from RunRecord rather than forced into that shape."""

    violation_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target: str
    plugin: str
    reason: str


class HashCheck(BaseModel):
    ok: bool
    expected: str
    actual: str


class EvidenceVerification(BaseModel):
    """Result of recomputing a run's stdout/stderr hashes from its stored
    output and comparing them against evidence.stdout_sha256/stderr_sha256.

    This only catches accidental or partial changes to the run's JSON file
    (a bad manual edit, disk corruption, a bug that mutates output without
    touching evidence). Anyone with write access to the file can edit both
    the output and the hash together, so this is not tamper-proof against a
    deliberate adversary with the same access — see AGENTS.md.
    """

    run_id: str
    stdout: HashCheck
    stderr: HashCheck
    ok: bool
