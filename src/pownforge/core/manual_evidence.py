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
    engagement: str | None = None,
    via_target: str | None = None,
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
    authorization rule as every other plugin name.

    ENGAGEMENT/VIA_TARGET record this step as a pivot: TARGET_NAME was
    reached via/from VIA_TARGET as part of ENGAGEMENT. Both must be given
    together, and ScopePolicy.authorize_pivot() checks that both targets
    are members of that Engagement -- this only authorizes recording the
    relationship, it never grants any execution right on its own (still
    requires TARGET_NAME's own allowed_plugins to include "manual")."""
    if (engagement is None) != (via_target is None):
        raise PolicyError("engagement and via_target must be given together, or not at all")

    try:
        target: Target = policy.authorize(target_name, MANUAL_PLUGIN_NAME)
        if engagement is not None and via_target is not None:
            policy.authorize_pivot(engagement, via_target, target_name)
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
        via_target=via_target,
        engagement=engagement,
    )
    store.save(record)
    return record
