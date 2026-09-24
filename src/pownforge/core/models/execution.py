from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from pownforge.core.models.primitive import Artifact

# --------------------------------------------------------------------------
# Execution layer (P0, refactor §4.2/§4.3/§4.7). ExecutionResult is the
# first-class result Plugin/Primitive execution deals in, built from a
# ProcessResult (core/process.py) in exactly one place
# (process.execution_result_from_process). ExecutionRequest started
# minimal ("run PLUGIN against TARGET with OPTIONS" as a first-class value
# instead of three positional arguments threaded through ScanRunner);
# refactor §18/P2 §9 adds the approval linkage (action_id/approval_id),
# populated by the ActionExecutor (core/operation/runner.py) for a SCAN
# action -- both None for a bare `pownforge scan <plugin>` run outside
# any AttackOperation, which has no Action/Approval to reference.
# --------------------------------------------------------------------------


class ExecutionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ExecutionResult(BaseModel):
    status: ExecutionStatus
    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime
    duration: float
    timed_out: bool
    artifacts: list[Artifact] = Field(default_factory=list)


class ExecutionRequest(BaseModel):
    target: str
    plugin: str
    options: dict[str, Any] = Field(default_factory=dict)
    # Set only when this request executes an AttackOperation Action (see
    # core/operation/model.py's Action/Approval) -- None for a scan run
    # outside any operation. approval_id references the Approval that
    # authorized action_id; an Action is only ever executed once approved
    # (core/operation/runner.py checks this before building the request).
    action_id: str | None = None
    approval_id: str | None = None
