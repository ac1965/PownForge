from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


@lab_app.command("add")
def lab_add(
    name: str,
    image: str = typer.Option(..., help="Container image to run as the attack-target host."),
    env: list[str] = typer.Option([], "--env", help="Container env var, key=value, may repeat."),
    kind: TargetKind = typer.Option(
        TargetKind.HOST, "--kind", help="Registered target kind: host (nmap) or url (web/api plugins)."
    ),
    port: Optional[int] = typer.Option(
        None, "--port", help="Container port; builds http(s)://<name>:<port> when --kind url."
    ),
    scheme: str = typer.Option("http", "--scheme", help="URL scheme to use when --kind url."),
    allowed_plugins: str = typer.Option(
        "", help="Comma-separated plugin names allowed for the auto-registered target; empty = all."
    ),
    register: bool = typer.Option(
        True, help="Also register the container as an authorized scan target."
    ),
    network: str = typer.Option(LAB_NETWORK, help="Isolated Docker network to attach to."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Start an attack-target container on the isolated lab network."""
    env_map: dict[str, str] = {}
    for item in env:
        if "=" not in item:
            typer.echo(f"error: --env must be key=value, got '{item}'", err=True)
            raise typer.Exit(code=1)
        key, value = item.split("=", 1)
        env_map[key] = value

    try:
        address = resolve_lab_target_address(name, kind, scheme, port)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    manager = LabManager(network=network)
    try:
        host = manager.add(name, image, env_map)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"started lab host '{host.name}' ({host.image}) on network '{network}'")

    if not register:
        return
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
    target = Target(
        name=name,
        kind=kind,
        address=address,
        allowed_plugins=plugins,
        notes=f"lab container on isolated docker network '{network}'",
    )
    try:
        target = target_service.register_target(config, target)
    except PolicyError as exc:
        typer.echo(f"warning: container started but target registration failed: {exc}", err=True)
        return
    typer.echo(f"registered target '{name}' -> {target.address} (resolves via docker DNS on '{network}')")


@lab_app.command("remove")
def lab_remove(
    name: str,
    purge: bool = typer.Option(False, help="Also remove the registered scan target."),
    network: str = typer.Option(LAB_NETWORK),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Stop and remove an attack-target container."""
    manager = LabManager(network=network)
    try:
        manager.remove(name)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"removed lab host '{name}'")

    if not purge:
        return
    try:
        target_service.remove_target(config, name)
    except PolicyError as exc:
        typer.echo(f"warning: {exc}", err=True)
        return
    typer.echo(f"removed target '{name}' from scope")


@lab_app.command("list")
def lab_list(network: str = typer.Option(LAB_NETWORK)) -> None:
    """List attack-target containers on the lab network."""
    manager = LabManager(network=network)
    try:
        hosts = manager.list()
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not hosts:
        typer.echo("no lab hosts running; use `pownforge lab add`")
        raise typer.Exit()
    for host in hosts:
        typer.echo(f"{host.name}\t{host.image}\t{host.status}")
