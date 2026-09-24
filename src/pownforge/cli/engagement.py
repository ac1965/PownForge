from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
    target_names = [t.strip() for t in targets.split(",") if t.strip()]
    engagement = Engagement(name=name, targets=target_names, notes=notes or None)
    try:
        with locked_policy(config) as policy:
            policy.add_engagement(engagement)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"registered engagement '{name}' with targets: {', '.join(target_names)}")
