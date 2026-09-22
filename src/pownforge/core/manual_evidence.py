from __future__ import annotations

import shlex
from datetime import datetime, timezone

from pownforge.core.models import Evidence, RunRecord, Target
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.secrets import mask_command
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.hashing import sha256_text
from pownforge.evidence.store import EvidenceStore

MANUAL_PLUGIN_NAME = "manual"


def import_manual_run(
    policy: ScopePolicy,
    store: EvidenceStore,
    target_name: str,
    command: str,
    output: str,
    *,
    tool: str | None = None,
    tool_version: str | None = None,
    returncode: int = 0,
    occurred_at: datetime | None = None,
    audit: AuditStore | None = None,
) -> RunRecord:
    """Record evidence for a step a human performed with an external tool
    (e.g. Metasploit, a manual exploit against a single already-authorized
    host) against a registered target.

    PownForge never runs COMMAND itself -- this only persists what the
    operator reports, through the same ScopePolicy authorization and
    EvidenceStore/hash pipeline a real plugin scan uses, so the step can be
    referenced by `pownforge walkthrough generate` and its evidence
    integrity checked with `pownforge evidence verify` like any other run.
    A target only accepts manual evidence if "manual" is in its
    allowed_plugins (or allowed_plugins is empty, meaning "any") -- the same
    authorization rule as every other plugin name."""
    try:
        target: Target = policy.authorize(target_name, MANUAL_PLUGIN_NAME)
    except PolicyError as exc:
        if audit is not None:
            audit.record(target=target_name, plugin=MANUAL_PLUGIN_NAME, reason=str(exc))
        raise

    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    evidence_command = mask_command(argv) if argv else [command]

    when = occurred_at or datetime.now(timezone.utc)
    evidence = Evidence(
        command=evidence_command,
        started_at=when,
        finished_at=when,
        returncode=returncode,
        stdout_sha256=sha256_text(output),
        stderr_sha256=sha256_text(""),
        tool_version=tool_version,
    )
    record = RunRecord(
        target=target.name,
        plugin=MANUAL_PLUGIN_NAME,
        created_at=when,
        evidence=evidence,
        output={"raw_stdout": output, "raw_stderr": "", "tool": tool or "manual"},
    )
    store.save(record)
    return record
