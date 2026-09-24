from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
