"""Composition root (refactor §18 step 2): the one place ScopePolicy,
EvidenceStore, AuditStore, ConcurrencyGuard, AttackSessionStore,
PrimitiveRunStore, AttackOperationStore, and the plugin PluginRegistry get
built from CONFIG/WORKDIR paths.

Before this module, cli.py's `_policy()`/`_store()`/`_audit()`/... and
web/deps.py's `get_policy()`/`get_store()`/`get_audit_store()`/... were two
separate implementations of exactly the same construction (see the
refactor audit: "配線の二重化"). Both now delegate here, so a third
front-end -- or a new Application Service that needs its own wiring --
has one place to build these from, not two to keep in sync.

Deliberately Typer/FastAPI-agnostic: nothing here parses arguments, reads
a Request, or raises typer.Exit/HTTPException."""

from __future__ import annotations

from pathlib import Path

from pownforge.core.attack_session import AttackSessionStore
from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.operation import AttackOperationStore
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry, default_registry
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.primitive_store import PrimitiveRunStore
from pownforge.evidence.store import EvidenceStore


def build_policy(config: Path) -> ScopePolicy:
    return ScopePolicy.load(config)


def build_registry() -> PluginRegistry:
    return default_registry()


def build_store(workdir: Path) -> EvidenceStore:
    return EvidenceStore(workdir / "runs")


def build_audit(workdir: Path) -> AuditStore:
    return AuditStore(workdir / "violations")


def build_concurrency(workdir: Path) -> ConcurrencyGuard:
    return ConcurrencyGuard(workdir / "active")


def build_attack_sessions(workdir: Path) -> AttackSessionStore:
    return AttackSessionStore(workdir / "attack_sessions")


def build_primitive_runs(workdir: Path) -> PrimitiveRunStore:
    return PrimitiveRunStore(workdir / "primitive_runs")


def build_operations(workdir: Path) -> AttackOperationStore:
    return AttackOperationStore(workdir / "operations")
