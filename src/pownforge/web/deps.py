from __future__ import annotations

from pathlib import Path

from fastapi import Depends, Request

from pownforge.core.attack_session import AttackSessionStore
from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.lab import LabManager, VulhubProvider
from pownforge.core.operation import PrimitiveRunner
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry, default_registry
from pownforge.core.runner import ScanRunner
from pownforge.core.settings import AppSettings, load_settings
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.primitive_store import PrimitiveRunStore
from pownforge.evidence.store import EvidenceStore
from pownforge.web.jobs import JobManager


def get_config_path(request: Request) -> Path:
    return request.app.state.config_path


def get_workdir(request: Request) -> Path:
    return request.app.state.workdir


def get_settings_path(request: Request) -> Path:
    return request.app.state.settings_path


def get_playbooks_dir(request: Request) -> Path:
    return request.app.state.playbooks_dir


def get_app_settings(path: Path = Depends(get_settings_path)) -> AppSettings:
    # Reloaded from disk on every request, same as get_policy, so a change
    # from the Settings page or `pownforge config set` is picked up
    # immediately without restarting the server.
    return load_settings(path)


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


def get_attack_sessions(workdir: Path = Depends(get_workdir)) -> AttackSessionStore:
    return AttackSessionStore(workdir / "attack_sessions")


def get_concurrency_guard(workdir: Path = Depends(get_workdir)) -> ConcurrencyGuard:
    return ConcurrencyGuard(workdir / "active")


def get_runner(
    policy: ScopePolicy = Depends(get_policy),
    registry: PluginRegistry = Depends(get_registry),
    store: EvidenceStore = Depends(get_store),
    audit: AuditStore = Depends(get_audit_store),
    concurrency: ConcurrencyGuard = Depends(get_concurrency_guard),
) -> ScanRunner:
    return ScanRunner(policy=policy, registry=registry, store=store, audit=audit, concurrency=concurrency)


def get_primitive_store(workdir: Path = Depends(get_workdir)) -> PrimitiveRunStore:
    return PrimitiveRunStore(workdir / "primitive_runs")


def get_primitive_runner(
    policy: ScopePolicy = Depends(get_policy),
    audit: AuditStore = Depends(get_audit_store),
) -> PrimitiveRunner:
    return PrimitiveRunner(policy=policy, audit=audit)


def get_lab_manager() -> LabManager:
    return LabManager()


def get_vulhub_dir(request: Request) -> Path:
    return request.app.state.vulhub_dir


def get_vulhub_provider(vulhub_dir: Path = Depends(get_vulhub_dir)) -> VulhubProvider:
    return VulhubProvider(vulhub_dir)


def get_job_manager(request: Request) -> JobManager:
    return request.app.state.jobs
