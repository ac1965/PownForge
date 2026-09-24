from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from pownforge.ai.ollama import OllamaAdapter
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
    TargetType,
    ValidationLevel,
)
from pownforge.core.policy import PolicyError, ScopePolicy
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


def _policy(config: Path) -> ScopePolicy:
    return ScopePolicy.load(config)


def _store(workdir: Path) -> EvidenceStore:
    return EvidenceStore(workdir / "runs")


def _audit(workdir: Path) -> AuditStore:
    return AuditStore(workdir / "violations")


def _concurrency(workdir: Path) -> ConcurrencyGuard:
    return ConcurrencyGuard(workdir / "active")


def _attack_sessions(workdir: Path) -> AttackSessionStore:
    return AttackSessionStore(workdir / "attack_sessions")


def _primitive_runs(workdir: Path) -> PrimitiveRunStore:
    return PrimitiveRunStore(workdir / "primitive_runs")


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


@app.command()
def init(
    workdir: Path = typer.Option(DEFAULT_WORKDIR, help="Local state directory for runs and reports."),
    config: Path = typer.Option(DEFAULT_CONFIG, help="Target scope file to create if missing."),
) -> None:
    """Initialize the local working directory and an empty scope file."""
    (workdir / "runs").mkdir(parents=True, exist_ok=True)
    (workdir / "reports").mkdir(parents=True, exist_ok=True)
    if not config.exists():
        ScopePolicy(targets={}).save(config)
        typer.echo(f"created empty scope file at {config}")
    typer.echo(f"initialized working directory at {workdir}")


@target_app.command("list")
def target_list(config: Path = typer.Option(DEFAULT_CONFIG)) -> None:
    """List registered targets."""
    policy = _policy(config)
    targets = policy.list_targets()
    if not targets:
        typer.echo("no targets registered; use `pownforge target add`")
        raise typer.Exit()
    for target in targets:
        allowed = ", ".join(target.allowed_plugins) or "any"
        type_ = target.type.value if target.type else "-"
        line = (
            f"{target.name}\t{target.kind.value}\t{target.address}\tplugins={allowed}"
            f"\ttype={type_}\tenv={target.environment.value}"
        )
        if target.max_concurrent is not None:
            line += f"\tmax_concurrent={target.max_concurrent}"
        if target.excluded:
            reason = f" ({target.exclusion_reason})" if target.exclusion_reason else ""
            line += f"\tEXCLUDED{reason}"
        typer.echo(line)


@target_app.command("add")
def target_add(
    name: str,
    address: str = typer.Option(..., help="Authorized host/IP or base URL for this target."),
    kind: TargetKind = typer.Option(TargetKind.HOST, help="host or url"),
    type: Optional[TargetType] = typer.Option(
        None, "--type", help="Assessment domain (network/web/api/kubernetes); purely descriptive."
    ),
    environment: TargetEnvironment = typer.Option(
        TargetEnvironment.LOCAL_LAB,
        "--environment",
        help="local-lab/staging/production. production requires --notes.",
    ),
    allowed_plugins: str = typer.Option(
        "", help="Comma-separated plugin names allowed for this target; empty = all."
    ),
    notes: str = typer.Option("", help="Free-text notes, e.g. engagement/authorization reference."),
    max_concurrent: Optional[int] = typer.Option(
        None, "--max-concurrent", help="Cap simultaneous scans against this target across every process; unset = unlimited."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Register a new authorized target."""
    policy = _policy(config)
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
    target = Target(
        name=name,
        kind=kind,
        address=address,
        allowed_plugins=plugins,
        notes=notes or None,
        type=type,
        environment=environment,
        max_concurrent=max_concurrent,
    )
    try:
        policy.add_target(target)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    policy.save(config)
    typer.echo(f"registered target '{name}' -> {address}")


@target_app.command("remove")
def target_remove(name: str, config: Path = typer.Option(DEFAULT_CONFIG)) -> None:
    """Unregister a target. To change a target's address/allowed_plugins/etc.,
    remove it and `target add` it again -- there is no in-place edit."""
    policy = _policy(config)
    try:
        policy.remove_target(name)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    policy.save(config)
    typer.echo(f"removed target '{name}'")


@target_app.command("exclude")
def target_exclude(
    name: str,
    reason: str = typer.Option("", "--reason", help="Why this target is temporarily off-limits."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Temporarily block every scan/manual/pivot against a registered target
    (e.g. a maintenance window, a stakeholder asked to pause) without
    unregistering it. Blocks every plugin, unlike --allowed-plugins which
    only narrows which ones are permitted."""
    policy = _policy(config)
    try:
        policy.exclude_target(name, reason or None)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    policy.save(config)
    typer.echo(f"excluded target '{name}'" + (f": {reason}" if reason else ""))


@target_app.command("include")
def target_include(name: str, config: Path = typer.Option(DEFAULT_CONFIG)) -> None:
    """Clear a target's exclusion, restoring its normal allowed_plugins scope."""
    policy = _policy(config)
    try:
        policy.include_target(name)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    policy.save(config)
    typer.echo(f"included target '{name}'")


@engagement_app.command("list")
def engagement_list(config: Path = typer.Option(DEFAULT_CONFIG)) -> None:
    """List registered engagements."""
    policy = _policy(config)
    engagements = policy.list_engagements()
    if not engagements:
        typer.echo("no engagements registered; use `pownforge engagement add`")
        raise typer.Exit()
    for engagement in engagements:
        typer.echo(f"{engagement.name}\ttargets={', '.join(engagement.targets)}")


@engagement_app.command("add")
def engagement_add(
    name: str,
    targets: str = typer.Option(
        ..., "--targets", help="Comma-separated names of already-registered targets to group."
    ),
    notes: str = typer.Option(
        "", help="Free-text notes, e.g. authorization/engagement reference (required if any member is production)."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Register a new Engagement grouping existing targets.

    Membership alone grants no execution rights on its own -- it only lets
    `pownforge result import --engagement ... --via ...` and `pownforge
    walkthrough generate --engagement ...` reference the members together.
    """
    policy = _policy(config)
    target_names = [t.strip() for t in targets.split(",") if t.strip()]
    engagement = Engagement(name=name, targets=target_names, notes=notes or None)
    try:
        policy.add_engagement(engagement)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    policy.save(config)
    typer.echo(f"registered engagement '{name}' with targets: {', '.join(target_names)}")


@playbook_app.command("list")
def playbook_list(playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir")) -> None:
    """List available playbooks."""
    playbooks = list_playbooks(playbooks_dir)
    if not playbooks:
        typer.echo(f"no playbooks found in {playbooks_dir}")
        raise typer.Exit()
    for playbook in playbooks:
        typer.echo(f"{playbook.name}\t{len(playbook.steps)} steps\t{playbook.description}")


@playbook_app.command("show")
def playbook_show(
    name: str, playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir")
) -> None:
    """Show a playbook's steps in order."""
    try:
        playbook = resolve_playbook(playbooks_dir, name)
    except PlaybookError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{playbook.name}: {playbook.description}")
    for i, step in enumerate(playbook.steps, start=1):
        options = ", ".join(f"{k}={v}" for k, v in step.options.items())
        line = f"  {i}. {step.plugin}" + (f" ({options})" if options else "")
        if step.when is not None:
            line += f" [when: step {step.when.after_step} has finding >= {step.when.min_severity.value}]"
        typer.echo(line)


@playbook_app.command("run")
def playbook_run(
    name: str,
    target: str = typer.Option(..., "--target"),
    playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir"),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run every step of a playbook against a registered target, in order.

    Each step goes through the same ScopePolicy authorization and evidence
    pipeline as `pownforge scan <plugin>` -- a playbook grants no execution
    right beyond what the target's own --allowed-plugins already permits
    for each step. A failing step does not stop the playbook; failures are
    still reported, never silently dropped."""
    try:
        playbook = resolve_playbook(playbooks_dir, name)
    except PlaybookError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    policy = _policy(config)
    registry = default_registry()
    store = _store(workdir)

    def on_step(index: int, total: int, step) -> None:  # noqa: ANN001
        typer.echo(f"[{index}/{total}] running {step.plugin}...")

    results = run_playbook(
        playbook,
        target,
        policy,
        registry,
        store,
        audit=_audit(workdir),
        on_step=on_step,
        concurrency=_concurrency(workdir),
    )

    run_ids: list[str] = []
    failures = 0
    skipped = 0
    for index, result in enumerate(results, start=1):
        if result.skipped:
            skipped += 1
            assert result.step.when is not None
            typer.echo(
                f"[{index}/{len(results)}] {result.step.plugin}: SKIPPED "
                f"(condition not met: step {result.step.when.after_step} needed a finding "
                f">= {result.step.when.min_severity.value})"
            )
        elif result.record is not None:
            run_ids.append(result.record.run_id)
            typer.echo(
                f"[{index}/{len(results)}] {result.step.plugin}: run {result.record.run_id} "
                f"completed (exit={result.record.evidence.returncode})"
            )
            if result.record.output.get("raw_stderr"):
                typer.echo(
                    f"  note: the tool wrote to stderr -- run `pownforge result show "
                    f"{result.record.run_id}` before assuming this step found what you expected",
                    err=True,
                )
        else:
            failures += 1
            typer.echo(f"[{index}/{len(results)}] {result.step.plugin}: FAILED -- {result.error}", err=True)

    typer.echo(
        f"playbook '{name}' finished: {len(results) - failures - skipped}/{len(results)} steps "
        f"succeeded ({skipped} skipped, {failures} failed)"
    )
    if run_ids:
        typer.echo(f"next: pownforge walkthrough generate {' '.join(run_ids)}")
    if failures:
        raise typer.Exit(code=1)


def _operations(workdir: Path) -> AttackOperationStore:
    return AttackOperationStore(workdir / "operations")


@primitive_app.command("list")
def primitive_list() -> None:
    """List available validation primitives and the options they accept."""
    for descriptor, options in list_primitives():
        typer.echo(
            f"{descriptor.id}\t[{descriptor.category}]\tmax_level={descriptor.max_level.value}"
            f"\t{descriptor.description}"
        )
        for opt in options:
            flag = " (required)" if opt.required else ""
            typer.echo(f"    --option {opt.name}{flag}: {opt.description}")


@primitive_app.command("run")
def primitive_run(
    primitive_id: str = typer.Argument(..., help="Primitive id (see `pownforge primitive list`)."),
    target: str = typer.Option(..., "--target"),
    level: ValidationLevel = typer.Option(
        ValidationLevel.VALIDATION,
        "--level",
        help="How far to go: detection, validation (default), or execution (dedicated lab only).",
    ),
    option: list[str] = typer.Option([], "--option", help="key=value, may repeat"),
    cve: list[str] = typer.Option(
        [], "--cve", help="CVE id this validation relates to, e.g. CVE-2021-44228. May repeat."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run a validation primitive against a registered target and persist the record.

    Scope and SafetyPolicy are enforced first (a refusal is recorded to the
    audit log); the primitive then runs its prepare/execute/observe/cleanup
    lifecycle. PownForge never runs an exploit -- see docs/handbook.md §15.
    """
    options: dict[str, str] = {}
    for item in option:
        if "=" not in item:
            typer.echo(f"error: --option must be key=value, got '{item}'", err=True)
            raise typer.Exit(code=1)
        key, value = item.split("=", 1)
        options[key] = value

    try:
        primitive = build_primitive(primitive_id, options)
    except PrimitiveError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    runner = PrimitiveRunner(_policy(config), audit=_audit(workdir))
    try:
        record = runner.run(primitive, target, level)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    record.cves = list(cve)
    _primitive_runs(workdir).save(record)

    typer.echo(f"primitive run {record.run_id} completed (level_reached={record.level_reached.value})")
    preconditions = ", ".join(f"{p.id}={p.status.value}" for p in record.preconditions.preconditions)
    typer.echo(f"preconditions: {preconditions or '(none)'}")
    if record.notes:
        typer.echo(f"note: {record.notes}")
    evidence = record.evidence
    if evidence is not None:
        typer.echo(
            f"evidence: observations={len(evidence.observations)} "
            f"findings={len(evidence.findings)} claims={len(evidence.claims)}"
        )
    if record.residual_resources:
        typer.echo(
            f"warning: {len(record.residual_resources)} resource(s) were not verified cleaned up "
            f"(see `pownforge primitive show {record.run_id}`)",
            err=True,
        )


@primitive_app.command("runs")
def primitive_runs(workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """List past primitive runs."""
    records = _primitive_runs(workdir).list()
    if not records:
        typer.echo("no primitive runs yet; use `pownforge primitive run`")
        raise typer.Exit()
    for record in records:
        residual = f"\tRESIDUAL={len(record.residual_resources)}" if record.residual_resources else ""
        typer.echo(
            f"{record.run_id}\t{record.primitive}\t{record.target}"
            f"\tlevel={record.level_reached.value}\t{record.created_at.isoformat()}{residual}"
        )


@primitive_app.command("show")
def primitive_show(
    run_id: str,
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Show a persisted primitive run record (preconditions, evidence, cleanup)."""
    try:
        record = _primitive_runs(workdir).load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(record.model_dump_json(indent=2))


@primitive_app.command("report")
def primitive_report(
    run_id: str,
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown, html, or pdf"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Render a report for a primitive run into <workdir>/reports/."""
    try:
        record = _primitive_runs(workdir).load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    if format == ReportFormat.PDF:
        report_path = reports_dir / f"{run_id}.pdf"
        report_path.write_bytes(_pdf_module().render_primitive(record))
    elif format == ReportFormat.HTML:
        report_path = reports_dir / f"{run_id}.html"
        report_path.write_text(primitive_report_render.render_html(record))
    else:
        report_path = reports_dir / f"{run_id}.md"
        report_path.write_text(primitive_report_render.render_markdown(record))
    typer.echo(f"wrote {report_path}")


@operation_app.command("create")
def operation_create(
    name: str,
    objective: str = typer.Option("", "--objective"),
    engagement: Optional[str] = typer.Option(None, "--engagement"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Create a new attack operation. Never executes anything -- this only
    registers a name to attach actions to via `operation add-action`."""
    try:
        create_operation(_operations(workdir), name, objective, engagement)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"created attack operation '{name}'")


@operation_app.command("show")
def operation_show(name: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Show an attack operation's nodes, edges, actions, and approvals."""
    try:
        operation = _operations(workdir).load(name)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{operation.name}: {operation.objective}")
    typer.echo(
        f"nodes={len(operation.nodes)} edges={len(operation.edges)} "
        f"actions={len(operation.actions)} approvals={len(operation.approvals)}"
    )
    for node in operation.nodes:
        typer.echo(f"  node {node.id}\ttarget={node.target}\tstate={node.state}\t{node.label}")
    for edge in operation.edges:
        caps = ",".join(c.value for c in edge.capabilities)
        typer.echo(f"  edge {edge.source} -> {edge.destination}\t{edge.relationship}\t[{caps}]")
    for action in operation.actions:
        typer.echo(f"  action {action.id}\t{action.phase.value}\t{action.kind.value}\t{action.target}\t{action.status.value}")


@operation_app.command("add-node")
def operation_add_node(
    name: str,
    node_id: str,
    target: str = typer.Option(..., "--target"),
    label: str = typer.Option("", "--label"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Add a node (an already-registered target) to an attack operation's graph.

    Purely descriptive bookkeeping -- this never authorizes anything beyond
    what TARGET's own allowed_plugins already permits."""
    try:
        add_node(_operations(workdir), _policy(config), name, node_id, target, label)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"added node '{node_id}' ({target})")


@operation_app.command("add-edge")
def operation_add_edge(
    name: str,
    source: str = typer.Option(..., "--source"),
    destination: str = typer.Option(..., "--destination"),
    capabilities: str = typer.Option(
        "", "--capabilities", help="Comma-separated Capability values; default: network-pivot."
    ),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Add an edge between two graph nodes (SOURCE, DESTINATION already added
    via `add-node`). Purely descriptive: recording an edge grants no
    execution or pivot right on its own -- a PIVOT action still needs its
    own approval and, at `execute` time, an Engagement that both targets
    belong to (see ScopePolicy.authorize_pivot())."""
    caps = [Capability(c.strip()) for c in capabilities.split(",") if c.strip()] or None
    try:
        add_edge(_operations(workdir), _policy(config), name, source, destination, caps)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"added edge '{source}' -> '{destination}'")


@operation_app.command("add-action")
def operation_add_action(
    name: str,
    action_id: str,
    action_name: str,
    target: str = typer.Option(..., "--target"),
    phase: AttackPhase = typer.Option(..., "--phase"),
    kind: ActionKind = typer.Option(ActionKind.SCAN, "--kind"),
    plugin: Optional[str] = typer.Option(None, "--plugin"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Add a candidate action (scan/manual/pivot) to an attack operation."""
    action = Action(id=action_id, name=action_name, phase=phase, kind=kind, target=target, plugin=plugin)
    try:
        add_action(_operations(workdir), _policy(config), name, action)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"added action '{action_id}'")


@operation_app.command("approve")
def operation_approve(
    name: str,
    action_id: str,
    approved_by: str = typer.Option(..., "--approved-by"),
    note: str = typer.Option("", "--note"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Record human approval for an action before it can be executed."""
    try:
        approve_action(_operations(workdir), name, action_id, approved_by, note)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"approved action '{action_id}'")


@operation_app.command("execute")
def operation_execute(
    name: str,
    action_id: str,
    command: Optional[str] = typer.Option(
        None, "--command", help="MANUAL/PIVOT only: what was actually run (defaults to the action's name)."
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        help="MANUAL/PIVOT only: transcript of the external tool's output. Required for these kinds -- "
        "PownForge never executes them itself, only records what a human already ran "
        "(same as `pownforge result import`).",
    ),
    tool: Optional[str] = typer.Option(None, "--tool", help="MANUAL/PIVOT only: external tool used."),
    tool_version: Optional[str] = typer.Option(None, "--tool-version"),
    returncode: int = typer.Option(0, "--returncode"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Execute an approved action.

    SCAN actions run through the existing ScanRunner, same as `pownforge
    scan <plugin>`. MANUAL/PIVOT actions never execute anything -- --output
    must already be the transcript of what a human ran with an external
    tool; this only records it (a PIVOT action additionally requires the
    operation to have an --engagement and a graph edge ending at the
    action's target, see `operation add-edge`)."""
    try:
        runner = OperationRunner(
            _policy(config), default_registry(), _store(workdir), _audit(workdir), concurrency=_concurrency(workdir)
        )
        updated = _operations(workdir).update(
            name,
            lambda operation: runner.execute(
                operation,
                action_id,
                manual_command=command,
                manual_output=output,
                manual_tool=tool,
                manual_tool_version=tool_version,
                manual_returncode=returncode,
            ),
        )
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"completed action '{action_id}' (run={next(a.run_id for a in updated.actions if a.id == action_id)})")


@attack_session_app.command("create")
def attack_session_create(
    name: str,
    description: str = typer.Option("", "--description"),
    engagement: Optional[str] = typer.Option(
        None, "--engagement", help="Cross-reference only, not validated against ScopePolicy."
    ),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Create a new, empty attack session. Never executes anything -- this
    only registers a name to attach stages to via `attack-session add-stage`."""
    try:
        create_attack_session(_attack_sessions(workdir), name, description=description, engagement=engagement)
    except AttackSessionError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"created attack session '{name}'")


@attack_session_app.command("add-stage")
def attack_session_add_stage(
    name: str,
    run_id: str,
    label: str = typer.Option("", "--label", help="Human-written note, e.g. 'Initial foothold via Shellshock'."),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Append an already-recorded run as the next stage of an attack session.
    RUN_ID must already exist (from `pownforge scan` or `pownforge result import`) --
    this never creates a run or executes anything."""
    try:
        session = add_stage(_attack_sessions(workdir), _store(workdir), name, run_id, label=label)
    except AttackSessionError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"added stage {len(session.stages)} ({run_id}) to attack session '{name}'")


@attack_session_app.command("list")
def attack_session_list(workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """List attack sessions."""
    sessions = _attack_sessions(workdir).list()
    if not sessions:
        typer.echo("no attack sessions recorded yet; use `pownforge attack-session create`")
        raise typer.Exit()
    for session in sessions:
        typer.echo(f"{session.name}\t{len(session.stages)} stages\t{session.description}")


@attack_session_app.command("show")
def attack_session_show(name: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Show an attack session's stages in order."""
    try:
        session = _attack_sessions(workdir).load(name)
    except AttackSessionError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{session.name}: {session.description}")
    if session.engagement:
        typer.echo(f"engagement: {session.engagement}")
    store = _store(workdir)
    for i, stage in enumerate(session.stages, start=1):
        try:
            record = store.load(stage.run_id)
            desc = f"{record.target} / {record.plugin}"
            if record.kill_chain_phase:
                desc += f" [{record.kill_chain_phase.value}]"
        except FileNotFoundError:
            desc = "(run no longer in evidence store)"
        label = f" — {stage.label}" if stage.label else ""
        typer.echo(f"  {i}. {stage.run_id}: {desc}{label}")


@plugin_app.command("list")
def plugin_list() -> None:
    """List available plugins and whether their tool is installed."""
    registry = default_registry()
    for plugin in registry.list():
        status = "ok" if plugin.check() else f"missing tool ({plugin.required_tool})"
        source = "" if plugin.source == "builtin" else f"\t[{plugin.source}]"
        typer.echo(f"{plugin.name}\tv{plugin.version}\t{status}\t{plugin.description}{source}")
    for error in registry.load_errors:
        typer.echo(f"warning: external plugin not loaded: {error}", err=True)


@plugin_app.command("info")
def plugin_info(name: str) -> None:
    """Show details for a single plugin, including the --option keys it accepts."""
    registry = default_registry()
    try:
        meta = registry.get(name).metadata()
    except RegistryError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"name: {meta.name}")
    typer.echo(f"version: {meta.version}")
    typer.echo(f"description: {meta.description}")
    typer.echo(f"source: {meta.source}")
    typer.echo(f"required tool: {meta.required_tool}")
    typer.echo(f"tool available: {meta.tool_available}")
    typer.echo(f"expected kind: {meta.expected_kind.value if meta.expected_kind else 'any'}")
    if meta.kind_hint:
        typer.echo(f"kind hint: {meta.kind_hint}")
    if meta.options is None:
        typer.echo("options: (not declared; not validated)")
        return
    typer.echo("options:" if meta.options else "options: (none)")
    for opt in meta.options:
        extras = []
        if opt.required:
            extras.append("required")
        if opt.default is not None:
            extras.append(f"default={opt.default}")
        if opt.choices is not None:
            extras.append(f"choices={'|'.join(opt.choices)}")
        suffix = f" [{', '.join(extras)}]" if extras else ""
        typer.echo(f"  {opt.name}: {opt.description}{suffix}")
    if meta.accepts_extra_options:
        typer.echo("  (other keys are passed through to the tool)")


def _run_scan(
    plugin_name: str,
    target: str,
    option: list[str],
    config: Path,
    workdir: Path,
    live: bool = False,
) -> None:
    options: dict[str, str] = {}
    for item in option:
        if "=" not in item:
            typer.echo(f"error: --option must be key=value, got '{item}'", err=True)
            raise typer.Exit(code=1)
        key, value = item.split("=", 1)
        options[key] = value

    policy = _policy(config)
    registry = default_registry()
    store = _store(workdir)
    runner = ScanRunner(
        policy=policy, registry=registry, store=store, audit=_audit(workdir), concurrency=_concurrency(workdir)
    )
    on_line = (lambda line: typer.echo(f"| {line}")) if live else None
    try:
        record = runner.run(target, plugin_name, options, on_line=on_line)
    except (PolicyError, RunnerError, PluginError, RegistryError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"run {record.run_id} completed (exit={record.evidence.returncode})")
    # A tool exiting 0 doesn't mean it found what you expected -- e.g. nmap
    # exits 0 on "0 hosts up" whether that's a genuinely empty result or a
    # DNS resolution failure. Flag non-empty stderr so a run that silently
    # did nothing useful doesn't look identical to a real result.
    if record.output.get("raw_stderr"):
        typer.echo(
            f"note: the tool wrote to stderr -- run `pownforge result show {record.run_id}` "
            "before assuming this run found what you expected",
            err=True,
        )


@scan_app.command("run")
def scan_run(
    plugin: str = typer.Argument(..., help="Plugin name (see `pownforge plugin list`), incl. external ones."),
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat (see `pownforge plugin info <plugin>`)"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run any registered plugin by name against a registered target."""
    _run_scan(plugin, target, option, config, workdir, live)


@scan_app.command("recon")
def scan_recon(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a bare domain name, e.g. example.com."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports sources=, exclude_sources="
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the recon plugin (subfinder: passive subdomain discovery from public sources) against a registered target."""
    _run_scan("recon", target, option, config, workdir, live)


@scan_app.command("network")
def scan_network(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option([], "--option", help="key=value, may repeat"),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the network plugin (nmap) against a registered target."""
    _run_scan("network", target, option, config, workdir, live)


@scan_app.command("web")
def scan_web(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; web plugin requires wordlist=<path>"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the web plugin (ffuf) against a registered target."""
    _run_scan("web", target, option, config, workdir, live)


@scan_app.command("api")
def scan_api(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat: path=/..., method=GET|HEAD|OPTIONS, timeout=<s>"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the api plugin (one curl request, passive header checks) against a registered url target."""
    _run_scan("api", target, option, config, workdir, live)


@scan_app.command("identity")
def scan_identity(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat: document=openid-configuration|oauth-authorization-server, timeout=<s>",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the identity plugin (fetch the public OIDC/OAuth discovery document once)."""
    _run_scan("identity", target, option, config, workdir, live)


@scan_app.command("httpx")
def scan_httpx(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat: paths=/,/admin,... paths_file=<file> timeout=<s>"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the httpx plugin (bulk HTTP probe of paths on one registered url target)."""
    _run_scan("httpx", target, option, config, workdir, live)


@scan_app.command("nuclei")
def scan_nuclei(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat; supports tags=, severity=, templates=",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the nuclei plugin (template-based vulnerability detection) against a registered target."""
    _run_scan("nuclei", target, option, config, workdir, live)


@scan_app.command("kubernetes")
def scan_kubernetes(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a kubeconfig context name."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports namespaces=, severity="
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the kubernetes plugin (trivy k8s: misconfig/RBAC/image vulnerabilities) against a registered target."""
    _run_scan("kubernetes", target, option, config, workdir, live)


@scan_app.command("kubernetes-audit")
def scan_kubernetes_audit(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a kubeconfig context name."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports namespaces= (trivy vulnerability scan scope)"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """One-shot RBAC/Pod Security/Network/Image attack-chain audit (kubectl + trivy k8s) against a registered target."""
    _run_scan("kubernetes-audit", target, option, config, workdir, live)


@scan_app.command("kube-bench")
def scan_kube_bench(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a kubeconfig context name."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports image= (default: pownforge-pownforge:latest), timeout="
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run kube-bench (CIS Kubernetes Benchmark) as an in-cluster Job against a registered target."""
    _run_scan("kube-bench", target, option, config, workdir, live)


@scan_app.command("sqlmap")
def scan_sqlmap(
    target: str = typer.Option(
        ..., "--target", help="Registered url target with an injectable parameter, e.g. .../item?id=1."
    ),
    option: list[str] = typer.Option(
        [],
        "--option",
        help=(
            "key=value, may repeat; supports risk=, level=, dump=true, dbs=true, etc. "
            "Options that escalate beyond SQLi (os-shell, file-read/write, tamper, ...) "
            "are rejected -- see docs/handbook.md #6."
        ),
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the sqlmap plugin (SQL injection detection/extraction) against a registered target."""
    _run_scan("sqlmap", target, option, config, workdir, live)


@scan_app.command("container")
def scan_container(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a container image reference."
    ),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat; supports severity=, ignore-unfixed=true, scanners=",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the container plugin (trivy image: vulnerabilities/misconfig/secrets) against a registered target."""
    _run_scan("container", target, option, config, workdir, live)


@scan_app.command("vulncheck")
def scan_vulncheck(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat; requires script=<name> (see `pownforge plugin info vulncheck`), optional port=",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the vulncheck plugin (a single, allowlisted nmap NSE 'vuln safe' script that verifies one known CVE) against a registered target."""
    _run_scan("vulncheck", target, option, config, workdir, live)


@result_app.command("list")
def result_list(workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """List past scan runs, most recent first."""
    store = _store(workdir)
    records = store.list()
    if not records:
        typer.echo("no runs recorded yet")
        raise typer.Exit()
    for record in records:
        typer.echo(f"{record.run_id}\t{record.created_at.isoformat()}\t{record.target}\t{record.plugin}")


@result_app.command("show")
def result_show(run_id: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Show the full JSON record for a run."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(record.model_dump_json(indent=2))


@result_app.command("import")
def result_import(
    target: str = typer.Option(
        ..., "--target", help="Registered target this was performed against."
    ),
    command: str = typer.Option(
        ..., "--command", help="What was run (e.g. an msfconsole invocation). Recorded as evidence, never executed."
    ),
    output: str = typer.Option(..., "--output", help="Paste of the external tool's output/session transcript."),
    tool: Optional[str] = typer.Option(None, "--tool", help="Name of the external tool used, e.g. 'msfconsole'."),
    tool_version: Optional[str] = typer.Option(None, "--tool-version"),
    returncode: int = typer.Option(0, "--returncode"),
    engagement: Optional[str] = typer.Option(
        None,
        "--engagement",
        help="Record this as a pivot step: TARGET was reached via --via, as part of this Engagement. "
        "Requires --via.",
    ),
    via: Optional[str] = typer.Option(
        None, "--via", help="The target TARGET was reached from/via. Requires --engagement."
    ),
    phase: Optional[KillChainPhase] = typer.Option(
        None,
        "--phase",
        help="Where this step sits in the attack chain (discovery/vuln-confirm/exploit/"
        "initial-access/privilege-escalation/lateral-movement/persistence/impact). Purely "
        "descriptive for reports/walkthroughs -- PownForge never executes anything based on it.",
    ),
    artifact: list[Path] = typer.Option(
        [],
        "--artifact",
        help="File to attach as proof (pcap, transcript, screenshot). May repeat. Copied into "
        "the evidence store and hashed at import time.",
    ),
    cve: list[str] = typer.Option(
        [], "--cve", help="CVE id this step relates to, e.g. CVE-2021-44228. May repeat."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Record evidence for a step performed manually with an external tool
    (e.g. Metasploit) against a registered target -- PownForge does not run
    COMMAND itself. The target must allow the 'manual' plugin name (or have
    an empty allowed_plugins list). See docs/handbook.md §13."""
    policy = _policy(config)
    store = _store(workdir)
    try:
        record = import_manual_run(
            policy,
            store,
            target,
            command,
            output,
            tool=tool,
            tool_version=tool_version,
            returncode=returncode,
            audit=_audit(workdir),
            engagement=engagement,
            via_target=via,
            kill_chain_phase=phase,
            artifacts=list(artifact) or None,
            cves=list(cve) or None,
        )
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"run {record.run_id} recorded (target={record.target}, plugin=manual)")
    for art in record.artifacts:
        typer.echo(f"  artifact: {art.description} -> {art.path} (sha256 {art.sha256})")


@result_app.command("tag")
def result_tag(
    run_id: str,
    cve: list[str] = typer.Option([], "--cve", help="CVE id to add (or remove with --remove). May repeat."),
    remove: bool = typer.Option(False, "--remove", help="Remove the given CVE ids instead of adding."),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Add or remove CVE tags on an existing run (scan or manual import). Tags
    are correlation labels for `report engagement`'s CVE exposure matrix."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not cve:
        typer.echo("error: pass at least one --cve", err=True)
        raise typer.Exit(code=1)
    if remove:
        record.cves = [c for c in record.cves if c not in cve]
    else:
        for c in cve:
            if c not in record.cves:
                record.cves.append(c)
    store.save(record)
    typer.echo(f"run {run_id} cves: {', '.join(record.cves) or '(none)'}")


@result_app.command("add-finding")
def result_add_finding(
    run_id: str,
    title: str = typer.Option(..., "--title"),
    severity: Severity = typer.Option(Severity.INFO, "--severity"),
    detail: str = typer.Option("", "--detail"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Attach a human-observed finding (source="manual") to an existing run."""
    store = _store(workdir)
    try:
        _, finding = add_finding(store, run_id, title, severity, detail)
    except FindingNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"finding '{finding.finding_id}' added to run '{run_id}' (status=needs-review)")


@result_app.command("review")
def result_review(
    run_id: str,
    finding_id: str,
    status: FindingStatus,
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Mark a finding as confirmed / false-positive / needs-review."""
    store = _store(workdir)
    try:
        review_finding(store, run_id, finding_id, status)
    except FindingNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"finding '{finding_id}' on run '{run_id}' -> {status.value}")


@audit_app.command("list")
def audit_list(workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """List rejected scan attempts, most recent first."""
    violations = _audit(workdir).list()
    if not violations:
        typer.echo("no policy violations recorded")
        raise typer.Exit()
    for violation in violations:
        typer.echo(
            f"{violation.violation_id}\t{violation.occurred_at.isoformat()}\t"
            f"{violation.target}\t{violation.plugin}\t{violation.reason}"
        )


@audit_app.command("show")
def audit_show(violation_id: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Show the full JSON record for a rejected scan attempt."""
    try:
        violation = _audit(workdir).load(violation_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(violation.model_dump_json(indent=2))


@evidence_app.command("verify")
def evidence_verify(run_id: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Recompute stdout/stderr hashes and compare against stored evidence."""
    store = _store(workdir)
    try:
        result = store.verify(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"stdout: {'OK' if result.stdout.ok else 'MISMATCH'}")
    typer.echo(f"stderr: {'OK' if result.stderr.ok else 'MISMATCH'}")
    if not result.ok:
        typer.echo(
            "warning: recorded evidence no longer matches the stored output for this run. "
            "This only detects accidental/partial changes to the run's JSON file — anyone "
            "who can edit that file can edit the hash to match, so this is not proof against "
            "deliberate tampering (see AGENTS.md).",
            err=True,
        )
        raise typer.Exit(code=1)
    typer.echo("evidence verified: hashes match stored output")


@report_app.command("generate")
def report_generate(
    run_id: str,
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown, html, or pdf"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Render a report for a run into <workdir>/reports/."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if format == ReportFormat.PDF:
        report_path = workdir / "reports" / f"{run_id}.pdf"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes(_pdf_module().render(record))
    elif format == ReportFormat.HTML:
        report_path = workdir / "reports" / f"{run_id}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(html_report.render(record))
    else:
        report_path = workdir / "reports" / f"{run_id}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(markdown.render(record))
    typer.echo(f"wrote {report_path}")


@report_app.command("engagement")
def report_engagement(
    target: Optional[str] = typer.Option(
        None, "--target", help="Scope to one target's runs (scans + primitives)."
    ),
    engagement: Optional[str] = typer.Option(
        None, "--engagement", help="Scope to an Engagement's members. Requires --config."
    ),
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown, html, or pdf"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG, help="Only read when --engagement is given."),
) -> None:
    """Render one cross-cutting engagement report over BOTH scan/manual runs
    and validation-primitive runs. Read-only; scope to a target, an
    Engagement, or (with neither) everything recorded (docs/handbook.md §13)."""
    if target and engagement:
        typer.echo("error: give either --target or --engagement, not both", err=True)
        raise typer.Exit(code=1)

    engagement_targets: list[str] | None = None
    scope_label = "all runs"
    if engagement:
        try:
            engagement_targets = _policy(config).resolve_engagement(engagement).targets
        except PolicyError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        scope_label = f"engagement: {engagement}"
        slug = f"engagement-{engagement}"
    elif target:
        scope_label = f"target: {target}"
        slug = f"target-{target}"
    else:
        slug = "all"

    try:
        report = collect_engagement(
            _store(workdir).list(),
            _primitive_runs(workdir).list(),
            target=target,
            engagement_targets=engagement_targets,
            scope_label=scope_label,
        )
    except EngagementReportError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    reports_dir = workdir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    if format == ReportFormat.PDF:
        report_path = reports_dir / f"engagement-{slug}.pdf"
        report_path.write_bytes(_pdf_module().render_engagement(report))
    elif format == ReportFormat.HTML:
        report_path = reports_dir / f"engagement-{slug}.html"
        report_path.write_text(engagement_report_render.render_html(report))
    else:
        report_path = reports_dir / f"engagement-{slug}.md"
        report_path.write_text(engagement_report_render.render_markdown(report))
    typer.echo(f"wrote {report_path}")


@attack_session_app.command("report")
def attack_session_report(
    name: str,
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown, html, or pdf"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Render an attack session's stages (in order) into <workdir>/reports/."""
    try:
        session = _attack_sessions(workdir).load(name)
    except AttackSessionError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    store = _store(workdir)
    try:
        records = [store.load(stage.run_id) for stage in session.stages]
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if format == ReportFormat.PDF:
        report_path = workdir / "reports" / f"attack-session-{name}.pdf"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes(_pdf_module().render_attack_session(session, records))
    elif format == ReportFormat.HTML:
        report_path = workdir / "reports" / f"attack-session-{name}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(attack_session_rendering.render_html(session, records))
    else:
        report_path = workdir / "reports" / f"attack-session-{name}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(attack_session_rendering.render_markdown(session, records))
    typer.echo(f"wrote {report_path}")


@walkthrough_app.command("generate")
def walkthrough_generate(
    run_ids: list[str] = typer.Argument(
        None, help="Run ids to include, in this order. Give either these or --target, not both."
    ),
    target: Optional[str] = typer.Option(
        None, "--target", help="Include every run recorded against this target, oldest first."
    ),
    engagement: Optional[str] = typer.Option(
        None,
        "--engagement",
        help="Include every run recorded against any member of this Engagement, oldest first "
        "(spans a lateral-movement chain). Requires --config to resolve the Engagement's members.",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="llm router model name (e.g. an Ollama model or 'claude-haiku-4.5'); "
        "defaults to `pownforge config`'s saved model.",
    ),
    language: Optional[Language] = typer.Option(
        None, "--language", help="Output language for the narrative/suggestions; "
        "defaults to `pownforge config`'s saved language."
    ),
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown or html"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    settings: Path = typer.Option(DEFAULT_SETTINGS, "--settings"),
    config: Path = typer.Option(DEFAULT_CONFIG, help="Only read when --engagement is given."),
) -> None:
    """Generate a narrative walkthrough connecting multiple runs, via the local LLM.

    Read-only: no run's stored findings/analysis are modified, unlike `analyze`.
    """
    store = _store(workdir)
    app_settings = load_settings(settings)
    adapter = OllamaAdapter(model=model or app_settings.model)
    engagement_targets: list[str] | None = None
    if engagement:
        try:
            engagement_targets = _policy(config).resolve_engagement(engagement).targets
        except PolicyError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    try:
        walkthrough = generate_walkthrough(
            store,
            adapter,
            run_ids or None,
            target,
            language=language or app_settings.language,
            targets=engagement_targets,
        )
    except WalkthroughError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    first_run_id = walkthrough.records[0].run_id
    if format == ReportFormat.HTML:
        report_path = workdir / "reports" / f"walkthrough-{first_run_id}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(walkthrough_report.render_html(walkthrough))
    else:
        report_path = workdir / "reports" / f"walkthrough-{first_run_id}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(walkthrough_report.render_markdown(walkthrough))
    typer.echo(f"wrote {report_path}")


@lab_app.command("add")
def lab_add(
    name: str,
    image: str = typer.Option(..., help="Container image to run as the attack-target host."),
    env: list[str] = typer.Option([], "--env", help="Container env var, key=value, may repeat."),
    kind: TargetKind = typer.Option(
        TargetKind.HOST, "--kind", help="Registered target kind: host (nmap) or url (web/api plugins)."
    ),
    port: Optional[int] = typer.Option(
        None, "--port", help="Container port; builds http(s)://<name>:<port> when --kind url."
    ),
    scheme: str = typer.Option("http", "--scheme", help="URL scheme to use when --kind url."),
    allowed_plugins: str = typer.Option(
        "", help="Comma-separated plugin names allowed for the auto-registered target; empty = all."
    ),
    register: bool = typer.Option(
        True, help="Also register the container as an authorized scan target."
    ),
    network: str = typer.Option(LAB_NETWORK, help="Isolated Docker network to attach to."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Start an attack-target container on the isolated lab network."""
    env_map: dict[str, str] = {}
    for item in env:
        if "=" not in item:
            typer.echo(f"error: --env must be key=value, got '{item}'", err=True)
            raise typer.Exit(code=1)
        key, value = item.split("=", 1)
        env_map[key] = value

    try:
        address = resolve_lab_target_address(name, kind, scheme, port)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    manager = LabManager(network=network)
    try:
        host = manager.add(name, image, env_map)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"started lab host '{host.name}' ({host.image}) on network '{network}'")

    if not register:
        return
    policy = _policy(config)
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
    target = Target(
        name=name,
        kind=kind,
        address=address,
        allowed_plugins=plugins,
        notes=f"lab container on isolated docker network '{network}'",
    )
    try:
        policy.add_target(target)
    except PolicyError as exc:
        typer.echo(f"warning: container started but target registration failed: {exc}", err=True)
        return
    policy.save(config)
    typer.echo(f"registered target '{name}' -> {address} (resolves via docker DNS on '{network}')")


@lab_app.command("remove")
def lab_remove(
    name: str,
    purge: bool = typer.Option(False, help="Also remove the registered scan target."),
    network: str = typer.Option(LAB_NETWORK),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Stop and remove an attack-target container."""
    manager = LabManager(network=network)
    try:
        manager.remove(name)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"removed lab host '{name}'")

    if not purge:
        return
    policy = _policy(config)
    try:
        policy.remove_target(name)
    except PolicyError as exc:
        typer.echo(f"warning: {exc}", err=True)
        return
    policy.save(config)
    typer.echo(f"removed target '{name}' from scope")


@lab_app.command("list")
def lab_list(network: str = typer.Option(LAB_NETWORK)) -> None:
    """List attack-target containers on the lab network."""
    manager = LabManager(network=network)
    try:
        hosts = manager.list()
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not hosts:
        typer.echo("no lab hosts running; use `pownforge lab add`")
        raise typer.Exit()
    for host in hosts:
        typer.echo(f"{host.name}\t{host.image}\t{host.status}")


@lab_kind_app.command("create")
def lab_kind_create(
    name: str,
    kind_config: Optional[Path] = typer.Option(
        None, "--kind-config", help="kind cluster config YAML (nodes, networking, ...)."
    ),
    kubeconfig_dir: Path = typer.Option(
        Path("config"), help="Where to write <name>.kubeconfig (git-ignored: holds cluster credentials)."
    ),
    allowed_plugins: str = typer.Option(
        "kubernetes,kubernetes-audit,kube-bench",
        help="Comma-separated plugin names allowed for the auto-registered target.",
    ),
    register: bool = typer.Option(True, help="Also register the cluster as an authorized scan target."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Create a kind cluster, export its in-docker-network kubeconfig, and register it."""
    manager = KindClusterManager()
    kubeconfig = kind_kubeconfig_path(kubeconfig_dir, name)
    try:
        cluster = manager.create(name, kubeconfig, kind_config)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"created kind cluster '{cluster.name}' (context {cluster.context})")
    typer.echo(f"wrote internal kubeconfig to {kubeconfig}")

    if not register:
        return
    policy = _policy(config)
    target = Target(
        name=name,
        kind=TargetKind.HOST,
        type=TargetType.KUBERNETES,
        address=cluster.context,
        allowed_plugins=[p.strip() for p in allowed_plugins.split(",") if p.strip()],
        notes=f"kind cluster created by `pownforge lab kind create`; KUBECONFIG={kubeconfig}",
    )
    try:
        policy.add_target(target)
    except PolicyError as exc:
        typer.echo(f"warning: cluster created but target registration failed: {exc}", err=True)
        return
    policy.save(config)
    typer.echo(f"registered target '{name}' -> {cluster.context}")
    typer.echo(f"scan with: KUBECONFIG={kubeconfig} pownforge scan kubernetes --target {name}")


@lab_kind_app.command("delete")
def lab_kind_delete(
    name: str,
    purge: bool = typer.Option(False, help="Also remove the registered scan target."),
    kubeconfig_dir: Path = typer.Option(Path("config")),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Delete a kind cluster and its exported kubeconfig."""
    manager = KindClusterManager()
    try:
        manager.delete(name)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"deleted kind cluster '{name}'")
    kubeconfig = kind_kubeconfig_path(kubeconfig_dir, name)
    if kubeconfig.exists():
        kubeconfig.unlink()
        typer.echo(f"removed {kubeconfig}")

    if not purge:
        return
    policy = _policy(config)
    try:
        policy.remove_target(name)
    except PolicyError as exc:
        typer.echo(f"warning: {exc}", err=True)
        return
    policy.save(config)
    typer.echo(f"removed target '{name}' from scope")


@lab_kind_app.command("list")
def lab_kind_list() -> None:
    """List kind clusters on this host."""
    try:
        clusters = KindClusterManager().list()
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not clusters:
        typer.echo("no kind clusters; use `pownforge lab kind create`")
        raise typer.Exit()
    for cluster in clusters:
        typer.echo(f"{cluster.name}\t{cluster.context}")


@lab_provider_app.command("list")
def lab_provider_list(
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir", help="Path to a Vulhub checkout."),
) -> None:
    """List Vulhub scenarios found under the checkout."""
    try:
        scenarios = VulhubProvider(vulhub_dir).list_scenarios()
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not scenarios:
        typer.echo(f"no scenarios found under {vulhub_dir}")
        raise typer.Exit()
    for scenario in scenarios:
        typer.echo(scenario.id)


@lab_provider_app.command("start")
def lab_provider_start(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
    register: bool = typer.Option(
        False, help="Also register the first published port as a url scan target on 127.0.0.1."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Start a Vulhub scenario (docker compose up -d)."""
    provider = VulhubProvider(vulhub_dir)
    try:
        started = provider.start(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"started scenario '{scenario}'")
    typer.echo(
        "warning: this is a deliberately-vulnerable environment; its compose file may publish "
        "ports on all interfaces. Run it only on an isolated lab host.",
        err=True,
    )
    for port in started.published_ports:
        typer.echo(f"  {port.service}: 127.0.0.1:{port.host_port} -> {port.container_port}")

    if not register:
        return
    if not started.published_ports:
        typer.echo("note: no published ports detected; nothing to register", err=True)
        return
    port = started.published_ports[0]
    name = vulhub_target_name(scenario)
    target = Target(
        name=name,
        kind=TargetKind.URL,
        address=f"http://127.0.0.1:{port.host_port}",
        notes=f"vulhub scenario '{scenario}' (deliberately vulnerable; lifecycle via `lab provider`)",
    )
    policy = _policy(config)
    try:
        policy.add_target(target)
    except PolicyError as exc:
        typer.echo(f"warning: scenario started but target registration failed: {exc}", err=True)
        return
    policy.save(config)
    typer.echo(f"registered target '{name}' -> {target.address}")


@lab_provider_app.command("status")
def lab_provider_status(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
) -> None:
    """Show whether a scenario is running and its published ports."""
    try:
        state = VulhubProvider(vulhub_dir).status(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{scenario}: {'running' if state.running else 'stopped'}")
    for port in state.published_ports:
        typer.echo(f"  {port.service}: 127.0.0.1:{port.host_port} -> {port.container_port}")


@lab_provider_app.command("stop")
def lab_provider_stop(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
) -> None:
    """Stop a scenario's containers (docker compose stop)."""
    try:
        VulhubProvider(vulhub_dir).stop(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"stopped scenario '{scenario}'")


@lab_provider_app.command("reset")
def lab_provider_reset(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
) -> None:
    """Recreate a scenario for a clean slate (docker compose down + up -d)."""
    try:
        VulhubProvider(vulhub_dir).reset(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"reset scenario '{scenario}'")


@lab_provider_app.command("cleanup")
def lab_provider_cleanup(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
    purge: bool = typer.Option(False, help="Also remove the auto-registered scan target, if present."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Tear a scenario down and remove its volumes (docker compose down -v)."""
    try:
        VulhubProvider(vulhub_dir).cleanup(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"cleaned up scenario '{scenario}'")

    if not purge:
        return
    policy = _policy(config)
    try:
        policy.remove_target(vulhub_target_name(scenario))
    except PolicyError as exc:
        typer.echo(f"warning: {exc}", err=True)
        return
    policy.save(config)
    typer.echo(f"removed target '{vulhub_target_name(scenario)}' from scope")


@app.command()
def analyze(
    run_id: str,
    model: Optional[str] = typer.Option(
        None,
        help="llm router model name (e.g. an Ollama model or 'claude-haiku-4.5'); "
        "defaults to `pownforge config`'s saved model.",
    ),
    language: Optional[Language] = typer.Option(
        None, "--language", help="Output language for the summary; "
        "defaults to `pownforge config`'s saved language."
    ),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    settings: Path = typer.Option(DEFAULT_SETTINGS, "--settings"),
) -> None:
    """Ask the local LLM router to classify findings and draft a summary for a run."""
    store = _store(workdir)
    app_settings = load_settings(settings)
    adapter = OllamaAdapter(model=model or app_settings.model)
    try:
        _, result = run_analysis(store, run_id, adapter, language=language or app_settings.language)
    except AnalysisError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not result.parsed:
        typer.echo(
            "warning: LLM response was not valid JSON; storing it as the summary text only "
            "(no structured findings extracted)",
            err=True,
        )

    typer.echo(result.summary)
    for finding in result.findings:
        typer.echo(f"- [{finding.severity.value}] {finding.title} — {finding.detail}")


@config_app.command("show")
def config_show(settings: Path = typer.Option(DEFAULT_SETTINGS, "--settings")) -> None:
    """Print the saved AI assistant preferences (model, language)."""
    app_settings = load_settings(settings)
    model_display = app_settings.model or "(unset -- uses the llm CLI's own default)"
    typer.echo(f"model: {model_display}")
    typer.echo(f"language: {app_settings.language.value}")


@config_app.command("set")
def config_set(
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="llm router model name to use by default (e.g. an Ollama model name, or "
        "'claude-haiku-4.5' once `llm keys set anthropic` has an API key). "
        "Pass '' (empty string) to unset and fall back to the `llm` CLI's own default.",
    ),
    language: Optional[Language] = typer.Option(
        None, "--language", help="Output language for analyze/walkthrough prose (ja or en)."
    ),
    settings: Path = typer.Option(DEFAULT_SETTINGS, "--settings"),
) -> None:
    """Update saved AI assistant preferences. Only given fields change."""
    app_settings = load_settings(settings)
    if model is not None:
        app_settings.model = model or None
    if language is not None:
        app_settings.language = language
    save_settings(app_settings, settings)
    typer.echo(f"wrote {settings}")
    config_show(settings)


@web_app.command("serve")
def web_serve(
    host: str = typer.Option(
        "127.0.0.1",
        help="Bind address. Binding beyond localhost exposes the scan/target/lab "
        "write APIs on that interface; there is no authentication in this version.",
    ),
    port: int = typer.Option(8420),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    settings: Path = typer.Option(DEFAULT_SETTINGS, "--settings"),
    playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir"),
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
    kubeconfig_dir: Path = typer.Option(Path("config"), "--kubeconfig-dir"),
) -> None:
    """Serve the PownForge web UI and API."""
    try:
        import uvicorn

        from pownforge.web.app import create_app
    except ImportError as exc:
        typer.echo(
            "error: the web UI needs extra dependencies. Install them with "
            "`pip install -e '.[web]'` and try again.",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    web_app_instance = create_app(
        config=config,
        workdir=workdir,
        settings=settings,
        playbooks_dir=playbooks_dir,
        vulhub_dir=vulhub_dir,
        kubeconfig_dir=kubeconfig_dir,
    )
    uvicorn.run(web_app_instance, host=host, port=port)


if __name__ == "__main__":
    app()
