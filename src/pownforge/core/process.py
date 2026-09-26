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
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterator

from pownforge.core.models import ExecutionResult, ExecutionStatus

OnLine = Callable[[str], None]


class ProcessLimitError(RuntimeError):
    """Raised by ProcessResourceLimiter.acquire() when a global concurrent-
    execution cap or a target's cumulative execution-time budget is already
    exhausted. core/runner.py catches this the same way it already catches
    ConcurrencyError (core/concurrency.py) and records it via AuditStore."""


def _env_positive_number(name: str, cast: Callable[[str], float]) -> float | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        value = cast(raw)
    except ValueError:
        return None
    return value if value > 0 else None


@dataclass
class ProcessResourceLimiter:
    """Refactor v3 §8: a lighter-weight complement to ConcurrencyGuard
    (core/concurrency.py). ConcurrencyGuard is cross-process and per-target
    (Target.max_concurrent, enforced via lock files so it survives separate
    CLI invocations); this is in-process only -- a single Python process's
    own guard against launching too many external tools at once, or letting
    one target's scans consume unbounded cumulative wall-clock time. That
    makes it most useful for long-lived processes that can queue many scans
    themselves, chiefly the web server's JobManager, not a one-shot CLI
    invocation which is already just one process.

    Both limits default to unlimited (None) so an unconfigured
    ProcessExecutor behaves exactly as before -- this is an opt-in safety
    net, not a new default restriction. State resets on process restart; it
    is deliberately not persisted (unlike ConcurrencyGuard's lock files),
    since it exists to protect one running process from itself, not to
    coordinate across processes."""

    max_concurrent: int | None = None
    max_target_seconds: float | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    _active: int = field(default=0, repr=False, compare=False)
    _target_seconds: dict[str, float] = field(default_factory=dict, repr=False, compare=False)

    @contextmanager
    def acquire(self, target_name: str) -> Iterator[None]:
        """No-op (no bookkeeping at all) when both limits are unset --
        the common case. Raises ProcessLimitError immediately rather than
        queuing, matching ConcurrencyGuard's style: a caller that wants to
        wait/retry can catch it and do so."""
        if self.max_concurrent is None and self.max_target_seconds is None:
            yield
            return

        with self._lock:
            if self.max_concurrent is not None and self._active >= self.max_concurrent:
                raise ProcessLimitError(
                    f"global concurrent execution limit reached ({self._active}/{self.max_concurrent} "
                    "external tool processes already running in this process); wait for one to finish and retry"
                )
            if self.max_target_seconds is not None:
                spent = self._target_seconds.get(target_name, 0.0)
                if spent >= self.max_target_seconds:
                    raise ProcessLimitError(
                        f"target '{target_name}' has already consumed {spent:.0f}s of its "
                        f"{self.max_target_seconds:.0f}s cumulative execution-time budget for this process"
                    )
            self._active += 1
        started = time.monotonic()
        try:
            yield
        finally:
            elapsed = time.monotonic() - started
            with self._lock:
                self._active -= 1
                self._target_seconds[target_name] = self._target_seconds.get(target_name, 0.0) + elapsed


# The default limiter every ProcessExecutor() shares unless a caller passes
# its own -- configured once from the environment (same convention as
# POWNFORGE_CONFIG/POWNFORGE_HOME etc. in cli/_shared.py), so every
# ScanRunner/ProcessExecutor built anywhere in one process (chiefly the web
# server's JobManager, which can have several scans in flight in the same
# process) shares one process-wide budget without having to be threaded
# through every constructor. Unset by default (unlimited), preserving prior
# behavior for anyone who hasn't opted in.
DEFAULT_PROCESS_LIMITER = ProcessResourceLimiter(
    max_concurrent=_env_positive_number("POWNFORGE_MAX_CONCURRENT_PROCESSES", int),
    max_target_seconds=_env_positive_number("POWNFORGE_MAX_TARGET_SECONDS", float),
)


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

    `limiter` (refactor v3 §8) defaults to the process-wide
    DEFAULT_PROCESS_LIMITER so unrelated ProcessExecutor instances built
    across ScanRunner/OperationRunner calls in the same process still share
    one global-concurrency/per-target-time budget; pass an explicit
    ProcessResourceLimiter() (or None) to opt out, e.g. in tests that must
    not share state with other tests in the same pytest process.
    """

    def __init__(self, limiter: ProcessResourceLimiter | None = DEFAULT_PROCESS_LIMITER) -> None:
        self._limiter = limiter

    def run(
        self,
        command: list[str],
        *,
        timeout: float,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        on_stdout_line: OnLine | None = None,
        target_name: str = "",
    ) -> ProcessResult:
        if os.name != "posix":
            raise NotImplementedError(
                f"ProcessExecutor requires POSIX process-group termination; "
                f"unsupported platform {os.name!r} is not currently supported"
            )
        if self._limiter is None:
            return self._run(command, timeout=timeout, cwd=cwd, env=env, on_stdout_line=on_stdout_line)
        with self._limiter.acquire(target_name):
            return self._run(command, timeout=timeout, cwd=cwd, env=env, on_stdout_line=on_stdout_line)

    @staticmethod
    def _run(
        command: list[str],
        *,
        timeout: float,
        cwd: str | None,
        env: dict[str, str] | None,
        on_stdout_line: OnLine | None,
    ) -> ProcessResult:
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
            ProcessExecutor._kill_process_group(proc)
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
