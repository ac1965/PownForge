from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from pownforge.core.models.finding import Finding
from pownforge.core.models.primitive import Artifact


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


class KillChainPhase(str, Enum):
    """Where a recorded run sits in a full attacker kill chain, for
    reporting/tracking purposes only -- this labels evidence, it never
    grants execution authority. PownForge's own plugins (ScanRunner) only
    ever produce DISCOVERY/VULN_CONFIRM-phase evidence; everything from
    EXPLOIT onward can only be attached via `pownforge result import`
    (a human describing what they did with another tool), never executed
    by PownForge itself. See core/manual_evidence.py and
    docs/handbook.md §11."""

    DISCOVERY = "discovery"
    VULN_CONFIRM = "vuln-confirm"
    EXPLOIT = "exploit"
    INITIAL_ACCESS = "initial-access"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    LATERAL_MOVEMENT = "lateral-movement"
    PERSISTENCE = "persistence"
    IMPACT = "impact"


class RunRecord(BaseModel):
    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str
    plugin: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Evidence
    output: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    analysis: str | None = None
    # Set only for a manually-imported run recorded as a pivot step (see
    # ScopePolicy.authorize_pivot()): the name of the Target this run's
    # `target` was reached via/from, and the Engagement both belong to.
    # None for every ordinary scan/manual run that isn't part of a
    # lateral-movement chain.
    via_target: str | None = None
    engagement: str | None = None
    # Set by the operator on `pownforge result import` (never inferred, and
    # never set for a plugin-run scan). Purely descriptive metadata for
    # reports/walkthroughs -- see KillChainPhase.
    kill_chain_phase: KillChainPhase | None = None
    # Files the operator attached on `pownforge result import --artifact`
    # (e.g. a pcap, a session transcript, a screenshot of an exploit). Copied
    # into the evidence store and hashed at import time; the bytes are the
    # human-run exploit step's proof, which PownForge stores but never
    # produces itself. Empty for ordinary plugin scans.
    artifacts: list[Artifact] = Field(default_factory=list)
    # CVE ids this run relates to (e.g. "CVE-2021-44228"), set by the operator
    # via `result import --cve` / `result tag`. Purely a correlation label for
    # the engagement report's CVE exposure matrix -- never inferred, never
    # gates execution.
    cves: list[str] = Field(default_factory=list)


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
