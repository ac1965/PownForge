"""The one place PownForge shells out to a long-running external tool for a
scan (nmap/ffuf/nuclei/sqlmap/...). Plugins never call subprocess themselves
(see plugins/base.py's build_command contract) -- ScanRunner hands this
class an argv and gets a ProcessResult back, so timeout handling and
process termination are defined exactly once instead of per plugin.

See the refactor instructions §4.2/§4.3.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from pownforge.core.models import ExecutionResult, ExecutionStatus

OnLine = Callable[[str], None]


@dataclass
class ProcessResult:
    """Low-level result of running one external process argv to completion.
    Deliberately thinner than ExecutionResult (core/models.py): no
    `artifacts`, no PownForge-level `status` -- just what the OS process
    itself did. execution_result_from_process() is the one place that
    turns this into the first-class ExecutionResult Plugin/Primitive
    execution deals in."""

    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime
    duration: float
    timed_out: bool


def _drain(stream, sink: list[str], on_line: OnLine | None) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)
        if on_line is not None:
            on_line(line.rstrip("\n"))
    stream.close()


class ProcessExecutor:
    """Runs one external command to completion: argv, env, cwd, stdout/
    stderr capture, the timeout, and process termination.

    POSIX only. The child is started in its own process group
    (start_new_session=True); a timeout kills the whole group with
    os.killpg, not just the immediate child -- a plugin's argv can itself
    spawn further children (a shell pipeline, a wrapper script), and
    killing only the direct child would leave those running. There is no
    process-group equivalent on Windows, and PownForge does not currently
    run there (docs/handbook.md's install path is POSIX-only), so run()
    raises NotImplementedError rather than silently leaving orphaned
    children behind on an unsupported platform.
    """

    def run(
        self,
        command: list[str],
        *,
        timeout: float,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        on_stdout_line: OnLine | None = None,
    ) -> ProcessResult:
        if os.name != "posix":
            raise NotImplementedError(
                f"ProcessExecutor requires POSIX process-group termination; "
                f"unsupported platform {os.name!r} is not currently supported"
            )
        started_at = datetime.now(timezone.utc)
        proc = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_lines, on_stdout_line))
        t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_lines, None))
        t_out.start()
        t_err.start()

        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_process_group(proc)
            proc.wait()
        t_out.join()
        t_err.join()
        finished_at = datetime.now(timezone.utc)

        return ProcessResult(
            exit_code=proc.returncode,
            stdout="".join(stdout_lines),
            stderr="".join(stderr_lines),
            started_at=started_at,
            finished_at=finished_at,
            duration=(finished_at - started_at).total_seconds(),
            timed_out=timed_out,
        )

    @staticmethod
    def _kill_process_group(proc: "subprocess.Popen[str]") -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            # The group leader already exited on its own between the
            # TimeoutExpired and here; nothing left to kill.
            pass


def execution_result_from_process(result: ProcessResult) -> ExecutionResult:
    """The one place a ProcessResult becomes the first-class ExecutionResult
    (see core/models.py). `artifacts` is always empty here -- a caller that
    collects artifacts (e.g. a Plugin's PluginExecution scratch files) adds
    them with `.model_copy(update={"artifacts": [...]})`."""
    if result.timed_out:
        status = ExecutionStatus.TIMED_OUT
    elif result.exit_code == 0:
        status = ExecutionStatus.SUCCEEDED
    else:
        status = ExecutionStatus.FAILED
    return ExecutionResult(
        status=status,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        started_at=result.started_at,
        finished_at=result.finished_at,
        duration=result.duration,
        timed_out=result.timed_out,
    )
