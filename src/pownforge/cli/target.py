from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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
        line = (
            f"{target.name}\t{target.kind.value}\t{target.address}\tplugins={allowed}"
            f"\ttype={type_}\tenv={target.environment.value}"
        )
        if target.max_concurrent is not None:
            line += f"\tmax_concurrent={target.max_concurrent}"
        if target.excluded:
            reason = f" ({target.exclusion_reason})" if target.exclusion_reason else ""
            line += f"\tEXCLUDED{reason}"
        typer.echo(line)


@target_app.command("add")
def target_add(
    name: str,
    address: str = typer.Option(
        ..., help="Authorized host/IP, base URL, or (for --kind path) a local directory."
    ),
    kind: TargetKind = typer.Option(TargetKind.HOST, help="host, url, or path"),
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
    max_concurrent: Optional[int] = typer.Option(
        None, "--max-concurrent", help="Cap simultaneous scans against this target across every process; unset = unlimited."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Register a new authorized target."""
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
    target = Target(
        name=name,
        kind=kind,
        address=address,
        allowed_plugins=plugins,
        notes=notes or None,
        type=type,
        environment=environment,
        max_concurrent=max_concurrent,
    )
    try:
        target = target_service.register_target(config, target)
    except (TargetPathError, PolicyError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"registered target '{target.name}' -> {target.address}")


@target_app.command("remove")
def target_remove(name: str, config: Path = typer.Option(DEFAULT_CONFIG)) -> None:
    """Unregister a target. To change a target's address/allowed_plugins/etc.,
    remove it and `target add` it again -- there is no in-place edit."""
    try:
        target_service.remove_target(config, name)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"removed target '{name}'")


@target_app.command("exclude")
def target_exclude(
    name: str,
    reason: str = typer.Option("", "--reason", help="Why this target is temporarily off-limits."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Temporarily block every scan/manual/pivot against a registered target
    (e.g. a maintenance window, a stakeholder asked to pause) without
    unregistering it. Blocks every plugin, unlike --allowed-plugins which
    only narrows which ones are permitted."""
    try:
        target_service.exclude_target(config, name, reason or None)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"excluded target '{name}'" + (f": {reason}" if reason else ""))


@target_app.command("include")
def target_include(name: str, config: Path = typer.Option(DEFAULT_CONFIG)) -> None:
    """Clear a target's exclusion, restoring its normal allowed_plugins scope."""
    try:
        target_service.include_target(config, name)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"included target '{name}'")
