from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


@web_app.command("serve")
def web_serve(
    host: str = typer.Option(
        "127.0.0.1",
        help="Bind address. Binding beyond localhost exposes the scan/target/lab "
        "write APIs on that interface; there is no authentication in this version.",
    ),
    port: int = typer.Option(8420),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    settings: Path = typer.Option(DEFAULT_SETTINGS, "--settings"),
    playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir"),
    vulhub_dir: Path = typer.Option(DEFAULT_VULHUB_DIR, "--vulhub-dir"),
    kubeconfig_dir: Path = typer.Option(Path("config"), "--kubeconfig-dir"),
) -> None:
    """Serve the PownForge web UI and API."""
    try:
        import uvicorn

        from pownforge.web.app import create_app
    except ImportError as exc:
        typer.echo(
            "error: the web UI needs extra dependencies. Install them with "
            "`pip install -e '.[web]'` and try again.",
            err=True,
        )
        raise typer.Exit(code=1) from exc

    web_app_instance = create_app(
        config=config,
        workdir=workdir,
        settings=settings,
        playbooks_dir=playbooks_dir,
        vulhub_dir=vulhub_dir,
        kubeconfig_dir=kubeconfig_dir,
    )
    uvicorn.run(web_app_instance, host=host, port=port)
