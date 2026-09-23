from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.models import Playbook
from pownforge.core.orchestrator import run_playbook
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import PluginError


@dataclass
class Job:
    job_id: str
    status: str = "pending"  # pending -> running -> done | error
    run_id: str | None = None
    error: str | None = None
    queue: "asyncio.Queue[dict[str, Any]]" = field(default_factory=asyncio.Queue)


@dataclass
class PlaybookJob:
    job_id: str
    status: str = "pending"  # pending -> running -> done
    run_ids: list[str] = field(default_factory=list)
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
        self._playbook_jobs: dict[str, PlaybookJob] = {}

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

    def submit_playbook(
        self,
        playbook: Playbook,
        target: str,
        policy: ScopePolicy,
        registry: PluginRegistry,
        store: EvidenceStore,
        audit: AuditStore | None = None,
        concurrency: ConcurrencyGuard | None = None,
    ) -> str:
        job_id = uuid.uuid4().hex[:12]
        job = PlaybookJob(job_id=job_id)
        self._playbook_jobs[job_id] = job
        loop = asyncio.get_running_loop()

        def on_step(index: int, total: int, step: Any) -> None:
            loop.call_soon_threadsafe(
                job.queue.put_nowait,
                {"type": "step_start", "index": index, "total": total, "plugin": step.plugin},
            )

        def work() -> None:
            job.status = "running"
            results = run_playbook(
                playbook, target, policy, registry, store, audit=audit, on_step=on_step, concurrency=concurrency
            )
            for index, result in enumerate(results, start=1):
                if result.skipped:
                    event = {"type": "step_skipped", "index": index, "plugin": result.step.plugin}
                elif result.record is not None:
                    job.run_ids.append(result.record.run_id)
                    event = {
                        "type": "step_done",
                        "index": index,
                        "plugin": result.step.plugin,
                        "run_id": result.record.run_id,
                        "returncode": result.record.evidence.returncode,
                    }
                else:
                    event = {
                        "type": "step_failed",
                        "index": index,
                        "plugin": result.step.plugin,
                        "error": result.error,
                    }
                loop.call_soon_threadsafe(job.queue.put_nowait, event)
            job.status = "done"
            loop.call_soon_threadsafe(
                job.queue.put_nowait, {"type": "done", "run_ids": list(job.run_ids)}
            )

        self._executor.submit(work)
        return job_id

    def get_playbook_job(self, job_id: str) -> PlaybookJob | None:
        return self._playbook_jobs.get(job_id)
