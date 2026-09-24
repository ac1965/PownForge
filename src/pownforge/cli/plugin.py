from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


@plugin_app.command("list")
def plugin_list() -> None:
    """List available plugins and whether their tool is installed."""
    registry = default_registry()
    for plugin in registry.list():
        status = "ok" if plugin.check() else f"missing tool ({plugin.required_tool})"
        source = "" if plugin.source == "builtin" else f"\t[{plugin.source}]"
        typer.echo(f"{plugin.name}\tv{plugin.version}\t{status}\t{plugin.description}{source}")
    for error in registry.load_errors:
        typer.echo(f"warning: external plugin not loaded: {error}", err=True)


@plugin_app.command("info")
def plugin_info(name: str) -> None:
    """Show details for a single plugin, including the --option keys it accepts."""
    registry = default_registry()
    try:
        meta = registry.get(name).metadata()
    except RegistryError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"name: {meta.name}")
    typer.echo(f"version: {meta.version}")
    typer.echo(f"description: {meta.description}")
    typer.echo(f"source: {meta.source}")
    typer.echo(f"required tool: {meta.required_tool}")
    typer.echo(f"tool available: {meta.tool_available}")
    typer.echo(f"expected kind: {meta.expected_kind.value if meta.expected_kind else 'any'}")
    if meta.kind_hint:
        typer.echo(f"kind hint: {meta.kind_hint}")
    if meta.options is None:
        typer.echo("options: (not declared; not validated)")
        return
    typer.echo("options:" if meta.options else "options: (none)")
    for opt in meta.options:
        extras = []
        if opt.required:
            extras.append("required")
        if opt.default is not None:
            extras.append(f"default={opt.default}")
        if opt.choices is not None:
            extras.append(f"choices={'|'.join(opt.choices)}")
        suffix = f" [{', '.join(extras)}]" if extras else ""
        typer.echo(f"  {opt.name}: {opt.description}{suffix}")
    if meta.accepts_extra_options:
        typer.echo("  (other keys are passed through to the tool)")
