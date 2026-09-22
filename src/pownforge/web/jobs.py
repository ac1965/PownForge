from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from pownforge.core.policy import PolicyError
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.plugins.base import PluginError


@dataclass
class Job:
    job_id: str
    status: str = "pending"  # pending -> running -> done | error
    run_id: str | None = None
    error: str | None = None
    queue: "asyncio.Queue[dict[str, Any]]" = field(default_factory=asyncio.Queue)


class JobManager:
    """Runs scans in a small background thread pool and fans each job's
    stdout lines out through an asyncio.Queue, so a WebSocket handler in the
    event loop can tail it live. Only intended for a single local user: one
    subscriber per job, no persistence of a job's queue across process
    restarts (finished/failed jobs are still recoverable via `get`, and the
    resulting run itself is always in EvidenceStore once done)."""

    def __init__(self, max_workers: int = 2) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: dict[str, Job] = {}

    def submit(
        self,
        runner: ScanRunner,
        target: str,
        plugin: str,
        options: dict[str, str],
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        job = Job(job_id=job_id)
        self._jobs[job_id] = job
        loop = asyncio.get_running_loop()

        def on_line(line: str) -> None:
            loop.call_soon_threadsafe(job.queue.put_nowait, {"type": "line", "data": line})

        def work() -> None:
            job.status = "running"
            try:
                record = runner.run(target, plugin, options, on_line=on_line)
            except (PolicyError, RunnerError, PluginError) as exc:
                job.status = "error"
                job.error = str(exc)
                loop.call_soon_threadsafe(job.queue.put_nowait, {"type": "error", "message": str(exc)})
                return
            job.status = "done"
            job.run_id = record.run_id
            loop.call_soon_threadsafe(
                job.queue.put_nowait,
                {"type": "done", "run_id": record.run_id, "returncode": record.evidence.returncode},
            )

        self._executor.submit(work)
        return job_id

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)
