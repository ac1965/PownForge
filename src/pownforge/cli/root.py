from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
