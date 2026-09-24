from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
