from __future__ import annotations

import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from pownforge.ai.ollama import OllamaAdapter
from pownforge.core.analysis import AnalysisError, run_analysis
from pownforge.core.attack_session import AttackSessionError, AttackSessionStore, add_stage, create_attack_session
from pownforge.core.findings import FindingNotFoundError, add_finding, review_finding
from pownforge.core.lab import LAB_NETWORK, LabError, LabManager, resolve_lab_target_address
from pownforge.core.manual_evidence import import_manual_run
from pownforge.core.orchestrator import (
    CampaignError,
    PlaybookError,
    list_campaigns,
    list_playbooks,
    resolve_campaign,
    resolve_playbook,
    run_campaign,
    run_playbook,
)
from pownforge.core.operation import (
    Action,
    ActionKind,
    ActionStatus,
    AttackOperationStore,
    AttackPhase,
    Capability,
    OperationError,
    OperationRunner,
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
)
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import default_registry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.core.settings import Language, load_settings, save_settings
from pownforge.core.walkthrough import WalkthroughError, generate_walkthrough
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import PluginError
from pownforge.reporting import attack_session as attack_session_rendering
from pownforge.reporting import html as html_report
from pownforge.reporting import markdown
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

app.add_typer(target_app, name="target")
app.add_typer(engagement_app, name="engagement")
playbook_app = typer.Typer(
    help="Run a pre-authored, linear sequence of plugin scans against one target "
    "(see config/playbooks/, docs/handbook.md §8)."
)
app.add_typer(playbook_app, name="playbook")
campaign_app = typer.Typer(
    help="Run a pre-authored Playbook against every target in a named Engagement, then "
    "record the results as a new AttackSession (see config/campaigns/, docs/handbook.md §8)."
)
app.add_typer(campaign_app, name="campaign")
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
app.add_typer(web_app, name="web")
app.add_typer(audit_app, name="audit")
app.add_typer(evidence_app, name="evidence")
app.add_typer(config_app, name="config")
app.add_typer(operation_app, name="operation")

DEFAULT_CONFIG = Path(os.environ.get("POWNFORGE_CONFIG", "config/targets.yaml"))
DEFAULT_WORKDIR = Path(os.environ.get("POWNFORGE_HOME", ".pownforge"))
DEFAULT_SETTINGS = Path(os.environ.get("POWNFORGE_SETTINGS", "config/settings.yaml"))
DEFAULT_PLAYBOOKS_DIR = Path(os.environ.get("POWNFORGE_PLAYBOOKS", "config/playbooks"))
DEFAULT_CAMPAIGNS_DIR = Path(os.environ.get("POWNFORGE_CAMPAIGNS", "config/campaigns"))


def _policy(config: Path) -> ScopePolicy:
    return ScopePolicy.load(config)


def _store(workdir: Path) -> EvidenceStore:
    return EvidenceStore(workdir / "runs")


def _audit(workdir: Path) -> AuditStore:
    return AuditStore(workdir / "violations")


def _attack_sessions(workdir: Path) -> AttackSessionStore:
    return AttackSessionStore(workdir / "attack_sessions")


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
        typer.echo(
            f"{target.name}\t{target.kind.value}\t{target.address}\tplugins={allowed}"
            f"\ttype={type_}\tenv={target.environment.value}"
        )


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
        playbook, target, policy, registry, store, audit=_audit(workdir), on_step=on_step
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


@campaign_app.command("list")
def campaign_list(campaigns_dir: Path = typer.Option(DEFAULT_CAMPAIGNS_DIR, "--campaigns-dir")) -> None:
    """List available campaigns."""
    campaigns = list_campaigns(campaigns_dir)
    if not campaigns:
        typer.echo(f"no campaigns found in {campaigns_dir}")
        raise typer.Exit()
    for campaign in campaigns:
        typer.echo(
            f"{campaign.name}\tengagement={campaign.engagement}\tplaybook={campaign.playbook}"
            f"\t{campaign.description}"
        )


@campaign_app.command("show")
def campaign_show(
    name: str, campaigns_dir: Path = typer.Option(DEFAULT_CAMPAIGNS_DIR, "--campaigns-dir")
) -> None:
    """Show a campaign's Engagement/Playbook reference."""
    try:
        campaign = resolve_campaign(campaigns_dir, name)
    except CampaignError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{campaign.name}: {campaign.description}")
    typer.echo(f"  engagement: {campaign.engagement}")
    typer.echo(f"  playbook:   {campaign.playbook}")


@campaign_app.command("run")
def campaign_run(
    name: str,
    session_name: Optional[str] = typer.Option(
        None,
        "--session-name",
        help="AttackSession name to create from this run's stages "
        "(default: '<campaign>-<UTC timestamp>').",
    ),
    campaigns_dir: Path = typer.Option(DEFAULT_CAMPAIGNS_DIR, "--campaigns-dir"),
    playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir"),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run a campaign's Playbook against every target in its Engagement, in order.

    This runs one full `playbook run` per target via the exact same
    ScanRunner/ScopePolicy path -- neither the campaign nor the Engagement
    grants any execution right beyond what each target's own
    --allowed-plugins already permits, and PownForge never lets one
    target's run reach another. A target whose playbook run can't start
    (e.g. it was removed from the scope file) does not stop the campaign
    for the remaining targets. Every successful step's run is recorded as a
    stage in a newly created AttackSession."""
    policy = _policy(config)
    try:
        campaign = resolve_campaign(campaigns_dir, name)
        playbook = resolve_playbook(playbooks_dir, campaign.playbook)
        engagement = policy.resolve_engagement(campaign.engagement)
    except (CampaignError, PlaybookError, PolicyError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not engagement.targets:
        typer.echo(f"error: engagement '{engagement.name}' has no members", err=True)
        raise typer.Exit(code=1)

    registry = default_registry()
    store = _store(workdir)

    def on_step(
        t_index: int, t_total: int, target_name: str, step_index: int, step_total: int, step
    ) -> None:  # noqa: ANN001
        typer.echo(f"[{t_index}/{t_total} {target_name}] [{step_index}/{step_total}] running {step.plugin}...")

    result = run_campaign(
        campaign, playbook, engagement, policy, registry, store, audit=_audit(workdir), on_step=on_step
    )

    total_steps = 0
    failed_steps = 0
    skipped_steps = 0
    for target_result in result.target_results:
        if target_result.error is not None:
            typer.echo(f"  {target_result.target_name}: FAILED -- {target_result.error}", err=True)
            continue
        for step_result in target_result.steps:
            total_steps += 1
            if step_result.skipped:
                skipped_steps += 1
                typer.echo(f"  {target_result.target_name}: {step_result.step.plugin}: SKIPPED")
            elif step_result.record is not None:
                typer.echo(
                    f"  {target_result.target_name}: {step_result.step.plugin}: "
                    f"run {step_result.record.run_id} completed"
                )
            else:
                failed_steps += 1
                typer.echo(
                    f"  {target_result.target_name}: {step_result.step.plugin}: FAILED -- {step_result.error}",
                    err=True,
                )

    stages = result.successful_stages()
    session_name_final = session_name or (
        f"{campaign.name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    sessions = _attack_sessions(workdir)
    create_attack_session(
        sessions, session_name_final, description=f"campaign '{campaign.name}' sweep", engagement=engagement.name
    )
    for label, record in stages:
        add_stage(sessions, store, session_name_final, record.run_id, label=label)

    typer.echo(
        f"campaign '{name}' finished: {total_steps - failed_steps - skipped_steps}/{total_steps} steps "
        f"succeeded across {len(engagement.targets)} targets ({skipped_steps} skipped, {failed_steps} failed)"
    )
    typer.echo(f"created attack session '{session_name_final}' with {len(stages)} stages")
    typer.echo(f"next: pownforge attack-session report {session_name_final}")
    if failed_steps or any(tr.error is not None for tr in result.target_results):
        raise typer.Exit(code=1)


def _operations(workdir: Path) -> AttackOperationStore:
    return AttackOperationStore(workdir / "operations")


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
    for action in operation.actions:
        typer.echo(f"  {action.id}\t{action.phase.value}\t{action.kind.value}\t{action.target}\t{action.status.value}")


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
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Execute an approved action through the existing scan runner."""
    try:
        operation = _operations(workdir).load(name)
        updated = OperationRunner(_policy(config), default_registry(), _store(workdir), _audit(workdir)).execute(
            operation, action_id
        )
        _operations(workdir).save(updated)
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
        typer.echo(f"{plugin.name}\tv{plugin.version}\t{status}\t{plugin.description}")


@plugin_app.command("info")
def plugin_info(name: str) -> None:
    """Show details for a single plugin."""
    registry = default_registry()
    plugin = registry.get(name)
    typer.echo(f"name: {plugin.name}")
    typer.echo(f"version: {plugin.version}")
    typer.echo(f"description: {plugin.description}")
    typer.echo(f"required tool: {plugin.required_tool}")
    typer.echo(f"tool available: {plugin.check()}")
    typer.echo(f"expected kind: {plugin.expected_kind.value if plugin.expected_kind else 'any'}")


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
    runner = ScanRunner(policy=policy, registry=registry, store=store, audit=_audit(workdir))
    on_line = (lambda line: typer.echo(f"| {line}")) if live else None
    try:
        record = runner.run(target, plugin_name, options, on_line=on_line)
    except (PolicyError, RunnerError, PluginError) as exc:
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
        )
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"run {record.run_id} recorded (target={record.target}, plugin=manual)")


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


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"


@report_app.command("generate")
def report_generate(
    run_id: str,
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown or html"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Render a report for a run into <workdir>/reports/."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if format == ReportFormat.HTML:
        report_path = workdir / "reports" / f"{run_id}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(html_report.render(record))
    else:
        report_path = workdir / "reports" / f"{run_id}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(markdown.render(record))
    typer.echo(f"wrote {report_path}")


@attack_session_app.command("report")
def attack_session_report(
    name: str,
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown or html"),
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

    if format == ReportFormat.HTML:
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
    campaigns_dir: Path = typer.Option(DEFAULT_CAMPAIGNS_DIR, "--campaigns-dir"),
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
        campaigns_dir=campaigns_dir,
    )
    uvicorn.run(web_app_instance, host=host, port=port)


if __name__ == "__main__":
    app()
