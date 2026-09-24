from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
