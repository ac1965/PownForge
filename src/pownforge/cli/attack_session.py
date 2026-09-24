from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
