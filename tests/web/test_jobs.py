from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import ScanRunner
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginExecution
from pownforge.web.jobs import JobManager


class EchoPlugin(Plugin):
    name = "echo"
    version = "0.0.1"
    description = "test double that echoes the target address"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        return ["echo", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution) -> dict[str, Any]:
        return {"raw_stdout": raw_stdout, "raw_stderr": raw_stderr}


def _runner(tmp_path: Path) -> ScanRunner:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.HOST, address="127.0.0.1"))
    registry = PluginRegistry()
    registry.register(EchoPlugin())
    store = EvidenceStore(tmp_path / "runs")
    return ScanRunner(policy=policy, registry=registry, store=store)


def test_job_streams_lines_then_completes(tmp_path: Path) -> None:
    manager = JobManager(max_workers=1)
    runner = _runner(tmp_path)

    async def scenario() -> list[dict[str, Any]]:
        job_id = manager.submit(runner, "lab", "echo", {})
        job = manager.get(job_id)
        assert job is not None
        messages = []
        while True:
            message = await asyncio.wait_for(job.queue.get(), timeout=5)
            messages.append(message)
            if message["type"] in ("done", "error"):
                break
        return messages

    messages = asyncio.run(scenario())
    assert messages[-1]["type"] == "done"
    assert "run_id" in messages[-1]
    assert any(m["type"] == "line" and "127.0.0.1" in m["data"] for m in messages)


def test_job_reports_error_for_unregistered_target(tmp_path: Path) -> None:
    manager = JobManager(max_workers=1)
    runner = _runner(tmp_path)

    async def scenario() -> dict[str, Any]:
        job_id = manager.submit(runner, "not-registered", "echo", {})
        job = manager.get(job_id)
        assert job is not None
        return await asyncio.wait_for(job.queue.get(), timeout=5)

    message = asyncio.run(scenario())
    assert message["type"] == "error"


def test_get_unknown_job_returns_none(tmp_path: Path) -> None:
    manager = JobManager(max_workers=1)
    assert manager.get("no-such-job") is None
