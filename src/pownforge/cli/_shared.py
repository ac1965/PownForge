"""Shared imports, Typer sub-app wiring, composition-root delegations, and
small cross-cutting helpers for the pownforge.cli package (refactor §18
step 3: cli.py split into one file per command group, kept behavior- and
output-identical -- `pownforge.cli:app`, the pyproject.toml entry point,
still resolves to the same Typer app; see
tests/test_characterization_baseline.py for the current command count).

Every `cli/<group>.py` module does `from pownforge.cli._shared import *`
to get everything it needs (Typer, the domain imports, the per-group
Typer sub-apps like `target_app`, DEFAULT_CONFIG/DEFAULT_WORKDIR/...,
and the _policy()/_store()/.../_pdf_module() helpers) without each command
file re-declaring its own import block -- this module is the single
place that surface is defined, listed explicitly in __all__ below since
several of those names (the `_xxx` helpers) start with an underscore and
`import *` skips those unless __all__ says otherwise."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from pownforge.ai.ollama import LLMAdapter
from pownforge.application.context import (
    build_attack_sessions,
    build_audit,
    build_concurrency,
    build_operations,
    build_policy,
    build_primitive_runs,
    build_store,
)
from pownforge.application import targets as target_service
from pownforge.core.analysis import AnalysisError, run_analysis
from pownforge.core.attack_session import AttackSessionError, AttackSessionStore, add_stage, create_attack_session
from pownforge.core.concurrency import ConcurrencyGuard
from pownforge.core.findings import FindingNotFoundError, add_finding, review_finding
from pownforge.core.lab import (
    LAB_NETWORK,
    KindClusterManager,
    LabError,
    LabManager,
    VulhubProvider,
    kind_kubeconfig_path,
    resolve_lab_target_address,
    vulhub_target_name,
)
from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.orchestrator import PlaybookError, list_playbooks, resolve_playbook, run_playbook
from pownforge.core.operation import (
    Action,
    ActionKind,
    ActionStatus,
    AttackOperationStore,
    AttackPhase,
    Capability,
    OperationError,
    OperationRunner,
    PrimitiveRunner,
    add_action,
    add_edge,
    add_node,
    approve_action,
    create_operation,
)
from pownforge.core.models import (
    Engagement,
    FindingStatus,
    KillChainPhase,
    Severity,
    Target,
    TargetEnvironment,
    TargetKind,
    TargetPathError,
    TargetType,
    ValidationLevel,
)
from pownforge.core.policy import PolicyError, ScopePolicy, locked_policy
from pownforge.core.registry import RegistryError, default_registry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.core.settings import Language, load_settings, save_settings
from pownforge.core.walkthrough import WalkthroughError, generate_walkthrough
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.primitive_store import PrimitiveRunStore
from pownforge.evidence.store import EvidenceStore
from pownforge.primitives.registry import PrimitiveError, build_primitive, list_primitives
from pownforge.plugins.base import PluginError
from pownforge.core.engagement_report import EngagementReportError, collect_engagement
from pownforge.reporting import attack_session as attack_session_rendering
from pownforge.reporting import engagement as engagement_report_render
from pownforge.reporting import html as html_report
from pownforge.reporting import markdown
from pownforge.reporting import primitive as primitive_report_render
from pownforge.reporting import walkthrough as walkthrough_report

app = typer.Typer(help="PownForge: a modular security assessment CLI for authorized engagements.")
target_app = typer.Typer(help="Manage the registered, authorized scan targets.")
engagement_app = typer.Typer(
    help="Manage Engagements: named groups of already-registered targets that may "
    "reference each other (e.g. a pivot/lateral-movement step)."
)
plugin_app = typer.Typer(help="Inspect available plugins.")
scan_app = typer.Typer(help="Run a plugin against a registered target.")
result_app = typer.Typer(help="Inspect past scan runs.")
report_app = typer.Typer(help="Generate Markdown/HTML reports from a run.")
walkthrough_app = typer.Typer(help="Generate a narrative walkthrough spanning multiple runs.")
lab_app = typer.Typer(help="Start/stop attack-target containers on an isolated lab network.")
web_app = typer.Typer(help=r"Serve the web UI (needs the \[web] extra: pip install -e '.\[web]').")
audit_app = typer.Typer(help="Inspect scan attempts that ScopePolicy rejected.")
evidence_app = typer.Typer(help="Verify stored evidence integrity.")
config_app = typer.Typer(help="View/update local AI assistant preferences (model, language).")
operation_app = typer.Typer(help="Plan and execute approved attack operations.")
primitive_app = typer.Typer(
    help="Run validation primitives (controlled validation + evidence + cleanup; "
    "detection/validation only, never exploit payloads -- see docs/handbook.md §15)."
)

app.add_typer(target_app, name="target")
app.add_typer(engagement_app, name="engagement")
playbook_app = typer.Typer(
    help="Run a pre-authored, linear sequence of plugin scans against one target "
    "(see config/playbooks/, docs/handbook.md §8)."
)
app.add_typer(playbook_app, name="playbook")
attack_session_app = typer.Typer(
    help="Group already-recorded runs into a named, curated engagement narrative "
    "(record/tracking only -- never executes anything, see docs/handbook.md §13)."
)
app.add_typer(attack_session_app, name="attack-session")
app.add_typer(plugin_app, name="plugin")
app.add_typer(scan_app, name="scan")
app.add_typer(result_app, name="result")
app.add_typer(report_app, name="report")
app.add_typer(walkthrough_app, name="walkthrough")
app.add_typer(lab_app, name="lab")
lab_kind_app = typer.Typer(help="Create/delete kind clusters as Kubernetes lab targets.")
lab_app.add_typer(lab_kind_app, name="kind")
lab_provider_app = typer.Typer(
    help="Manage external vulnerable-environment catalogues (Vulhub): "
    "list/start/status/stop/reset/cleanup. Lifecycle only -- PownForge never "
    "exploits them (see docs/handbook.md §7)."
)
lab_app.add_typer(lab_provider_app, name="provider")
app.add_typer(web_app, name="web")
app.add_typer(audit_app, name="audit")
app.add_typer(evidence_app, name="evidence")
app.add_typer(config_app, name="config")
app.add_typer(operation_app, name="operation")
app.add_typer(primitive_app, name="primitive")

DEFAULT_CONFIG = Path(os.environ.get("POWNFORGE_CONFIG", "config/targets.yaml"))
DEFAULT_WORKDIR = Path(os.environ.get("POWNFORGE_HOME", ".pownforge"))
DEFAULT_SETTINGS = Path(os.environ.get("POWNFORGE_SETTINGS", "config/settings.yaml"))
DEFAULT_PLAYBOOKS_DIR = Path(os.environ.get("POWNFORGE_PLAYBOOKS", "config/playbooks"))
DEFAULT_VULHUB_DIR = Path(os.environ.get("POWNFORGE_VULHUB_DIR", "vulhub"))


# Thin delegations to the composition root (application/context.py,
# refactor §18 step 2) -- kept as these short names since they're used
# throughout this file, but the actual construction lives in one place
# shared with web/deps.py.
def _policy(config: Path) -> ScopePolicy:
    return build_policy(config)


def _store(workdir: Path) -> EvidenceStore:
    return build_store(workdir)


def _audit(workdir: Path) -> AuditStore:
    return build_audit(workdir)


def _concurrency(workdir: Path) -> ConcurrencyGuard:
    return build_concurrency(workdir)


def _attack_sessions(workdir: Path) -> AttackSessionStore:
    return build_attack_sessions(workdir)


def _primitive_runs(workdir: Path) -> PrimitiveRunStore:
    return build_primitive_runs(workdir)


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"


def _pdf_module():  # noqa: ANN202
    try:
        from pownforge.reporting import pdf as pdf_report
    except ImportError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    return pdf_report

__all__ = [
    "Action",
    "ActionKind",
    "ActionStatus",
    "AnalysisError",
    "AttackOperationStore",
    "AttackPhase",
    "AttackSessionError",
    "AttackSessionStore",
    "AuditStore",
    "Capability",
    "ConcurrencyGuard",
    "DEFAULT_CONFIG",
    "DEFAULT_PLAYBOOKS_DIR",
    "DEFAULT_SETTINGS",
    "DEFAULT_VULHUB_DIR",
    "DEFAULT_WORKDIR",
    "Engagement",
    "EngagementReportError",
    "Enum",
    "EvidenceStore",
    "FindingNotFoundError",
    "FindingStatus",
    "KillChainPhase",
    "KindClusterManager",
    "LAB_NETWORK",
    "LLMAdapter",
    "LabError",
    "LabManager",
    "Language",
    "OperationError",
    "OperationRunner",
    "Optional",
    "Path",
    "PlaybookError",
    "PluginError",
    "PolicyError",
    "PrimitiveError",
    "PrimitiveRunStore",
    "PrimitiveRunner",
    "RegistryError",
    "ReportFormat",
    "RunnerError",
    "ScanRunner",
    "ScopePolicy",
    "Severity",
    "Target",
    "TargetEnvironment",
    "TargetKind",
    "TargetPathError",
    "TargetType",
    "ValidationLevel",
    "VulhubProvider",
    "WalkthroughError",
    "_attack_sessions",
    "_audit",
    "_concurrency",
    "_pdf_module",
    "_policy",
    "_primitive_runs",
    "_store",
    "add_action",
    "add_edge",
    "add_finding",
    "add_node",
    "add_stage",
    "app",
    "approve_action",
    "attack_session_app",
    "attack_session_rendering",
    "audit_app",
    "build_attack_sessions",
    "build_audit",
    "build_concurrency",
    "build_operations",
    "build_policy",
    "build_primitive",
    "build_primitive_runs",
    "build_store",
    "collect_engagement",
    "config_app",
    "create_attack_session",
    "create_operation",
    "default_registry",
    "engagement_app",
    "engagement_report_render",
    "evidence_app",
    "generate_walkthrough",
    "html_report",
    "import_manual_run",
    "kind_kubeconfig_path",
    "lab_app",
    "lab_kind_app",
    "lab_provider_app",
    "list_playbooks",
    "list_primitives",
    "load_settings",
    "locked_policy",
    "markdown",
    "operation_app",
    "os",
    "playbook_app",
    "plugin_app",
    "primitive_app",
    "primitive_report_render",
    "report_app",
    "resolve_lab_target_address",
    "resolve_playbook",
    "result_app",
    "review_finding",
    "run_analysis",
    "run_playbook",
    "save_settings",
    "scan_app",
    "target_app",
    "target_service",
    "typer",
    "vulhub_target_name",
    "walkthrough_app",
    "walkthrough_report",
    "web_app",
]
