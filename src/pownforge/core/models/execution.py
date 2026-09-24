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
# (process.execution_result_from_process). ExecutionRequest is deliberately
# minimal here -- approval linkage and further fields are P2's job; P0 only
# needs "run PLUGIN against TARGET with OPTIONS" as a first-class value
# instead of three positional arguments threaded through ScanRunner.
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
