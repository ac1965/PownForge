from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer

from pownforge.ai.ollama import OllamaAdapter, OllamaError
from pownforge.core.lab import LAB_NETWORK, LabError, LabManager
from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import default_registry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import PluginError
from pownforge.reporting import markdown

app = typer.Typer(help="PownForge: a modular security assessment CLI for authorized engagements.")
target_app = typer.Typer(help="Manage the registered, authorized scan targets.")
plugin_app = typer.Typer(help="Inspect available plugins.")
scan_app = typer.Typer(help="Run a plugin against a registered target.")
result_app = typer.Typer(help="Inspect past scan runs.")
report_app = typer.Typer(help="Generate Markdown reports from a run.")
lab_app = typer.Typer(help="Start/stop attack-target containers on an isolated lab network.")

app.add_typer(target_app, name="target")
app.add_typer(plugin_app, name="plugin")
app.add_typer(scan_app, name="scan")
app.add_typer(result_app, name="result")
app.add_typer(report_app, name="report")
app.add_typer(lab_app, name="lab")

DEFAULT_CONFIG = Path(os.environ.get("POWNFORGE_CONFIG", "config/targets.yaml"))
DEFAULT_WORKDIR = Path(os.environ.get("POWNFORGE_HOME", ".pownforge"))


def _policy(config: Path) -> ScopePolicy:
    return ScopePolicy.load(config)


def _store(workdir: Path) -> EvidenceStore:
    return EvidenceStore(workdir / "runs")


@app.command()
def init(
    workdir: Path = typer.Option(DEFAULT_WORKDIR, help="Local state directory for runs and reports."),
    config: Path = typer.Option(DEFAULT_CONFIG, help="Target scope file to create if missing."),
) -> None:
    """Initialize the local working directory and an empty scope file."""
    (workdir / "runs").mkdir(parents=True, exist_ok=True)
    (workdir / "reports").mkdir(parents=True, exist_ok=True)
    if not config.exists():
        ScopePolicy(targets={}).save(config)
        typer.echo(f"created empty scope file at {config}")
    typer.echo(f"initialized working directory at {workdir}")


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
        typer.echo(f"{target.name}\t{target.kind.value}\t{target.address}\tplugins={allowed}")


@target_app.command("add")
def target_add(
    name: str,
    address: str = typer.Option(..., help="Authorized host/IP or base URL for this target."),
    kind: TargetKind = typer.Option(TargetKind.HOST, help="host or url"),
    allowed_plugins: str = typer.Option(
        "", help="Comma-separated plugin names allowed for this target; empty = all."
    ),
    notes: str = typer.Option("", help="Free-text notes, e.g. engagement/authorization reference."),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Register a new authorized target."""
    policy = _policy(config)
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
    target = Target(name=name, kind=kind, address=address, allowed_plugins=plugins, notes=notes or None)
    try:
        policy.add_target(target)
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    policy.save(config)
    typer.echo(f"registered target '{name}' -> {address}")


@plugin_app.command("list")
def plugin_list() -> None:
    """List available plugins and whether their tool is installed."""
    registry = default_registry()
    for plugin in registry.list():
        status = "ok" if plugin.check() else f"missing tool ({plugin.required_tool})"
        typer.echo(f"{plugin.name}\tv{plugin.version}\t{status}\t{plugin.description}")


@plugin_app.command("info")
def plugin_info(name: str) -> None:
    """Show details for a single plugin."""
    registry = default_registry()
    plugin = registry.get(name)
    typer.echo(f"name: {plugin.name}")
    typer.echo(f"version: {plugin.version}")
    typer.echo(f"description: {plugin.description}")
    typer.echo(f"required tool: {plugin.required_tool}")
    typer.echo(f"tool available: {plugin.check()}")


def _run_scan(plugin_name: str, target: str, option: list[str], config: Path, workdir: Path) -> None:
    options: dict[str, str] = {}
    for item in option:
        if "=" not in item:
            typer.echo(f"error: --option must be key=value, got '{item}'", err=True)
            raise typer.Exit(code=1)
        key, value = item.split("=", 1)
        options[key] = value

    policy = _policy(config)
    registry = default_registry()
    store = _store(workdir)
    runner = ScanRunner(policy=policy, registry=registry, store=store)
    try:
        record = runner.run(target, plugin_name, options)
    except (PolicyError, RunnerError, PluginError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"run {record.run_id} completed (exit={record.evidence.returncode})")


@scan_app.command("network")
def scan_network(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option([], "--option", help="key=value, may repeat"),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the network plugin (nmap) against a registered target."""
    _run_scan("network", target, option, config, workdir)


@scan_app.command("web")
def scan_web(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; web plugin requires wordlist=<path>"
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the web plugin (ffuf) against a registered target."""
    _run_scan("web", target, option, config, workdir)


@result_app.command("list")
def result_list(workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """List past scan runs, most recent first."""
    store = _store(workdir)
    records = store.list()
    if not records:
        typer.echo("no runs recorded yet")
        raise typer.Exit()
    for record in records:
        typer.echo(f"{record.run_id}\t{record.created_at.isoformat()}\t{record.target}\t{record.plugin}")


@result_app.command("show")
def result_show(run_id: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Show the full JSON record for a run."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(record.model_dump_json(indent=2))


@report_app.command("generate")
def report_generate(run_id: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Render a Markdown report for a run into <workdir>/reports/."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    report_path = workdir / "reports" / f"{run_id}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(markdown.render(record))
    typer.echo(f"wrote {report_path}")


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

    if kind == TargetKind.URL and port is None:
        typer.echo("error: --port is required when --kind url is used", err=True)
        raise typer.Exit(code=1)

    manager = LabManager(network=network)
    try:
        host = manager.add(name, image, env_map)
    except LabError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"started lab host '{host.name}' ({host.image}) on network '{network}'")

    if not register:
        return
    policy = _policy(config)
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
    address = f"{scheme}://{name}:{port}" if kind == TargetKind.URL else name
    target = Target(
        name=name,
        kind=kind,
        address=address,
        allowed_plugins=plugins,
        notes=f"lab container on isolated docker network '{network}'",
    )
    try:
        policy.add_target(target)
    except PolicyError as exc:
        typer.echo(f"warning: container started but target registration failed: {exc}", err=True)
        return
    policy.save(config)
    typer.echo(f"registered target '{name}' -> {address} (resolves via docker DNS on '{network}')")


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
    policy = _policy(config)
    try:
        policy.remove_target(name)
    except PolicyError as exc:
        typer.echo(f"warning: {exc}", err=True)
        return
    policy.save(config)
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


@app.command()
def analyze(
    run_id: str,
    model: Optional[str] = typer.Option(
        None, help="Ollama model name to request from the local llm router."
    ),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Ask the local LLM router to draft an analysis of a run's findings."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    adapter = OllamaAdapter(model=model)
    prompt = (
        "You are assisting a human penetration tester in reviewing raw tool output. "
        "Summarize findings, call out anything worth manual follow-up, and flag likely false "
        "positives. Do not claim confirmed vulnerabilities from output alone.\n\n"
        f"Target: {record.target}\nPlugin: {record.plugin}\n\n"
        f"Raw output:\n{record.output.get('raw_stdout', '')}"
    )
    try:
        analysis = adapter.analyze(prompt)
    except OllamaError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    record.analysis = analysis
    store.save(record)
    typer.echo(analysis)


if __name__ == "__main__":
    app()
