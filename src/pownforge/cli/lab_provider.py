from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


@lab_provider_app.command("list")
def lab_provider_list(
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir", help="Path to a Vulhub checkout."),
) -> None:
    """List Vulhub scenarios found under the checkout."""
    try:
        scenarios = VulhubProvider(vulhub_dir).list_scenarios()
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not scenarios:
        typer.echo(f"no scenarios found under {vulhub_dir}")
        raise typer.Exit()
    for scenario in scenarios:
        typer.echo(scenario.id)


@lab_provider_app.command("start")
def lab_provider_start(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
    register: bool = typer.Option(
        False, help="Also register the first published port as a url scan target on 127.0.0.1."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Start a Vulhub scenario (docker compose up -d)."""
    provider = VulhubProvider(vulhub_dir)
    try:
        started = provider.start(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"started scenario '{scenario}'")
    typer.echo(
        "warning: this is a deliberately-vulnerable environment; its compose file may publish "
        "ports on all interfaces. Run it only on an isolated lab host.",
        err=True,
    )
    for port in started.published_ports:
        typer.echo(f"  {port.service}: 127.0.0.1:{port.host_port} -> {port.container_port}")

    if not register:
        return
    if not started.published_ports:
        typer.echo("note: no published ports detected; nothing to register", err=True)
        return
    port = started.published_ports[0]
    name = vulhub_target_name(scenario)
    target = Target(
        name=name,
        kind=TargetKind.URL,
        address=f"http://127.0.0.1:{port.host_port}",
        notes=f"vulhub scenario '{scenario}' (deliberately vulnerable; lifecycle via `lab provider`)",
    )
    try:
        target = target_service.register_target(config, target)
    except PolicyError as exc:
        typer.echo(f"warning: scenario started but target registration failed: {exc}", err=True)
        return
    typer.echo(f"registered target '{name}' -> {target.address}")


@lab_provider_app.command("status")
def lab_provider_status(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
) -> None:
    """Show whether a scenario is running and its published ports."""
    try:
        state = VulhubProvider(vulhub_dir).status(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{scenario}: {'running' if state.running else 'stopped'}")
    for port in state.published_ports:
        typer.echo(f"  {port.service}: 127.0.0.1:{port.host_port} -> {port.container_port}")


@lab_provider_app.command("stop")
def lab_provider_stop(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
) -> None:
    """Stop a scenario's containers (docker compose stop)."""
    try:
        VulhubProvider(vulhub_dir).stop(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"stopped scenario '{scenario}'")


@lab_provider_app.command("reset")
def lab_provider_reset(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
) -> None:
    """Recreate a scenario for a clean slate (docker compose down + up -d)."""
    try:
        VulhubProvider(vulhub_dir).reset(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"reset scenario '{scenario}'")


@lab_provider_app.command("cleanup")
def lab_provider_cleanup(
    scenario: str,
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
    purge: bool = typer.Option(False, help="Also remove the auto-registered scan target, if present."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Tear a scenario down and remove its volumes (docker compose down -v)."""
    try:
        VulhubProvider(vulhub_dir).cleanup(scenario)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"cleaned up scenario '{scenario}'")

    if not purge:
        return
    try:
        target_service.remove_target(config, vulhub_target_name(scenario))
    except PolicyError as exc:
        typer.echo(f"warning: {exc}", err=True)
        return
    typer.echo(f"removed target '{vulhub_target_name(scenario)}' from scope")
