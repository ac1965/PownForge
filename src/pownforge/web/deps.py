from __future__ import annotations

from pathlib import Path

from fastapi import Depends, Request

from pownforge.core.lab import LabManager
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry, default_registry
from pownforge.core.runner import ScanRunner
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.web.jobs import JobManager


def get_config_path(request: Request) -> Path:
    return request.app.state.config_path


def get_workdir(request: Request) -> Path:
    return request.app.state.workdir


def get_policy(config: Path = Depends(get_config_path)) -> ScopePolicy:
    # Reloaded from disk on every request, same as each CLI invocation does,
    # so on-disk edits (by the CLI or another web request) are always seen.
    return ScopePolicy.load(config)


def get_registry() -> PluginRegistry:
    return default_registry()


def get_store(workdir: Path = Depends(get_workdir)) -> EvidenceStore:
    return EvidenceStore(workdir / "runs")


def get_audit_store(workdir: Path = Depends(get_workdir)) -> AuditStore:
    return AuditStore(workdir / "violations")


def get_runner(
    policy: ScopePolicy = Depends(get_policy),
    registry: PluginRegistry = Depends(get_registry),
    store: EvidenceStore = Depends(get_store),
    audit: AuditStore = Depends(get_audit_store),
) -> ScanRunner:
    return ScanRunner(policy=policy, registry=registry, store=store, audit=audit)


def get_lab_manager() -> LabManager:
    return LabManager()


def get_job_manager(request: Request) -> JobManager:
    return request.app.state.jobs
