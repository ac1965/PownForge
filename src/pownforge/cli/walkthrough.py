from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
