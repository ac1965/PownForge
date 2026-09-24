from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
