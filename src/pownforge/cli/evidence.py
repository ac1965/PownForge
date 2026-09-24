from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
