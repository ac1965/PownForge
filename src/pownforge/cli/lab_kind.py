from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


@lab_kind_app.command("create")
def lab_kind_create(
    name: str,
    kind_config: Optional[Path] = typer.Option(
        None, "--kind-config", help="kind cluster config YAML (nodes, networking, ...)."
    ),
    kubeconfig_dir: Path = typer.Option(
        Path("config"), help="Where to write <name>.kubeconfig (git-ignored: holds cluster credentials)."
    ),
    allowed_plugins: str = typer.Option(
        "kubernetes,kubernetes-audit,kube-bench",
        help="Comma-separated plugin names allowed for the auto-registered target.",
    ),
    register: bool = typer.Option(True, help="Also register the cluster as an authorized scan target."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Create a kind cluster, export its in-docker-network kubeconfig, and register it."""
    manager = KindClusterManager()
    kubeconfig = kind_kubeconfig_path(kubeconfig_dir, name)
    try:
        cluster = manager.create(name, kubeconfig, kind_config)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"created kind cluster '{cluster.name}' (context {cluster.context})")
    typer.echo(f"wrote internal kubeconfig to {kubeconfig}")

    if not register:
        return
    target = Target(
        name=name,
        kind=TargetKind.HOST,
        type=TargetType.KUBERNETES,
        address=cluster.context,
        allowed_plugins=[p.strip() for p in allowed_plugins.split(",") if p.strip()],
        notes=f"kind cluster created by `pownforge lab kind create`; KUBECONFIG={kubeconfig}",
    )
    try:
        target = target_service.register_target(config, target)
    except PolicyError as exc:
        typer.echo(f"warning: cluster created but target registration failed: {exc}", err=True)
        return
    typer.echo(f"registered target '{target.name}' -> {target.address}")
    typer.echo(f"scan with: KUBECONFIG={kubeconfig} pownforge scan kubernetes --target {name}")


@lab_kind_app.command("delete")
def lab_kind_delete(
    name: str,
    purge: bool = typer.Option(False, help="Also remove the registered scan target."),
    kubeconfig_dir: Path = typer.Option(Path("config")),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Delete a kind cluster and its exported kubeconfig."""
    manager = KindClusterManager()
    try:
        manager.delete(name)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"deleted kind cluster '{name}'")
    kubeconfig = kind_kubeconfig_path(kubeconfig_dir, name)
    if kubeconfig.exists():
        kubeconfig.unlink()
        typer.echo(f"removed {kubeconfig}")

    if not purge:
        return
    try:
        target_service.remove_target(config, name)
    except PolicyError as exc:
        typer.echo(f"warning: {exc}", err=True)
        return
    typer.echo(f"removed target '{name}' from scope")


@lab_kind_app.command("list")
def lab_kind_list() -> None:
    """List kind clusters on this host."""
    try:
        clusters = KindClusterManager().list()
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not clusters:
        typer.echo("no kind clusters; use `pownforge lab kind create`")
        raise typer.Exit()
    for cluster in clusters:
        typer.echo(f"{cluster.name}\t{cluster.context}")
