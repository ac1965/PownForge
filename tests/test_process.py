"""P0 §4.2/§4.3: ProcessExecutor and the ProcessResult -> ExecutionResult
conversion."""

from __future__ import annotations

import os
import time

import pytest

from pownforge.core.models import ExecutionStatus
from pownforge.core.process import ProcessExecutor, ProcessResult, execution_result_from_process


def test_process_executor_captures_stdout_stderr_and_exit_code() -> None:
    result = ProcessExecutor().run(
        ["sh", "-c", "echo out; echo err >&2; exit 3"], timeout=5
    )
    assert result.exit_code == 3
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"
    assert result.timed_out is False
    assert result.duration >= 0


def test_process_executor_streams_stdout_lines() -> None:
    seen: list[str] = []
    ProcessExecutor().run(
        ["sh", "-c", "echo one; echo two"], timeout=5, on_stdout_line=seen.append
    )
    assert seen == ["one", "two"]


def test_process_executor_timeout_kills_the_whole_process_group(tmp_path) -> None:
    """The required P0 test: a timed-out command's children AND
    grandchildren must be terminated, not just the immediate child. A
    plain proc.kill() (no process group) would leave the grandchild
    running -- this proves killpg() is actually being used."""
    marker = tmp_path / "grandchild-still-running"
    marker.write_text("not yet")
    # Direct child spawns a detached grandchild that sleeps, then itself
    # sleeps past the timeout. If only the direct child is killed, the
    # grandchild survives and eventually overwrites the marker.
    script = (
        f"(sleep 5 && echo dead > {marker}) & disown; sleep 5"
    )
    result = ProcessExecutor().run(["sh", "-c", script], timeout=0.3)
    assert result.timed_out is True

    # Give a wrongly-surviving grandchild ample time to have written the
    # marker if it wasn't actually killed.
    time.sleep(1.5)
    assert marker.read_text() == "not yet", "grandchild process was not terminated with the group"


def test_process_executor_raises_on_non_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    with pytest.raises(NotImplementedError):
        ProcessExecutor().run(["true"], timeout=5)


def test_execution_result_from_process_maps_success() -> None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    process_result = ProcessResult(
        exit_code=0, stdout="ok", stderr="", started_at=now, finished_at=now, duration=0.1, timed_out=False
    )
    execution_result = execution_result_from_process(process_result)
    assert execution_result.status == ExecutionStatus.SUCCEEDED
    assert execution_result.artifacts == []


def test_execution_result_from_process_maps_failure() -> None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    process_result = ProcessResult(
        exit_code=1, stdout="", stderr="boom", started_at=now, finished_at=now, duration=0.1, timed_out=False
    )
    assert execution_result_from_process(process_result).status == ExecutionStatus.FAILED


def test_execution_result_from_process_maps_timeout() -> None:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    process_result = ProcessResult(
        exit_code=-9, stdout="", stderr="", started_at=now, finished_at=now, duration=5.0, timed_out=True
    )
    assert execution_result_from_process(process_result).status == ExecutionStatus.TIMED_OUT
