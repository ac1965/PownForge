from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from pownforge.ai.ollama import OllamaAdapter
from pownforge.core.analysis import AnalysisError, run_analysis
from pownforge.core.findings import FindingNotFoundError, review_finding
from pownforge.core.lab import LAB_NETWORK, LabError, LabManager, resolve_lab_target_address
from pownforge.core.models import FindingStatus, Target, TargetEnvironment, TargetKind, TargetType
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.core.registry import default_registry
from pownforge.core.runner import RunnerError, ScanRunner
from pownforge.core.walkthrough import WalkthroughError, generate_walkthrough
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import PluginError
from pownforge.reporting import html as html_report
from pownforge.reporting import markdown
from pownforge.reporting import walkthrough as walkthrough_report

app = typer.Typer(help="PownForge: a modular security assessment CLI for authorized engagements.")
target_app = typer.Typer(help="Manage the registered, authorized scan targets.")
plugin_app = typer.Typer(help="Inspect available plugins.")
scan_app = typer.Typer(help="Run a plugin against a registered target.")
result_app = typer.Typer(help="Inspect past scan runs.")
report_app = typer.Typer(help="Generate Markdown/HTML reports from a run.")
walkthrough_app = typer.Typer(help="Generate a narrative walkthrough spanning multiple runs.")
lab_app = typer.Typer(help="Start/stop attack-target containers on an isolated lab network.")
web_app = typer.Typer(help=r"Serve the web UI (needs the \[web] extra: pip install -e '.\[web]').")
audit_app = typer.Typer(help="Inspect scan attempts that ScopePolicy rejected.")
evidence_app = typer.Typer(help="Verify stored evidence integrity.")

app.add_typer(target_app, name="target")
app.add_typer(plugin_app, name="plugin")
app.add_typer(scan_app, name="scan")
app.add_typer(result_app, name="result")
app.add_typer(report_app, name="report")
app.add_typer(walkthrough_app, name="walkthrough")
app.add_typer(lab_app, name="lab")
app.add_typer(web_app, name="web")
app.add_typer(audit_app, name="audit")
app.add_typer(evidence_app, name="evidence")

DEFAULT_CONFIG = Path(os.environ.get("POWNFORGE_CONFIG", "config/targets.yaml"))
DEFAULT_WORKDIR = Path(os.environ.get("POWNFORGE_HOME", ".pownforge"))


def _policy(config: Path) -> ScopePolicy:
    return ScopePolicy.load(config)


def _store(workdir: Path) -> EvidenceStore:
    return EvidenceStore(workdir / "runs")


def _audit(workdir: Path) -> AuditStore:
    return AuditStore(workdir / "violations")


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
        type_ = target.type.value if target.type else "-"
        typer.echo(
            f"{target.name}\t{target.kind.value}\t{target.address}\tplugins={allowed}"
            f"\ttype={type_}\tenv={target.environment.value}"
        )


@target_app.command("add")
def target_add(
    name: str,
    address: str = typer.Option(..., help="Authorized host/IP or base URL for this target."),
    kind: TargetKind = typer.Option(TargetKind.HOST, help="host or url"),
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
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Register a new authorized target."""
    policy = _policy(config)
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
    target = Target(
        name=name,
        kind=kind,
        address=address,
        allowed_plugins=plugins,
        notes=notes or None,
        type=type,
        environment=environment,
    )
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
    typer.echo(f"expected kind: {plugin.expected_kind.value if plugin.expected_kind else 'any'}")


def _run_scan(
    plugin_name: str,
    target: str,
    option: list[str],
    config: Path,
    workdir: Path,
    live: bool = False,
) -> None:
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
    runner = ScanRunner(policy=policy, registry=registry, store=store, audit=_audit(workdir))
    on_line = (lambda line: typer.echo(f"| {line}")) if live else None
    try:
        record = runner.run(target, plugin_name, options, on_line=on_line)
    except (PolicyError, RunnerError, PluginError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"run {record.run_id} completed (exit={record.evidence.returncode})")


@scan_app.command("network")
def scan_network(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option([], "--option", help="key=value, may repeat"),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the network plugin (nmap) against a registered target."""
    _run_scan("network", target, option, config, workdir, live)


@scan_app.command("web")
def scan_web(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; web plugin requires wordlist=<path>"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the web plugin (ffuf) against a registered target."""
    _run_scan("web", target, option, config, workdir, live)


@scan_app.command("nuclei")
def scan_nuclei(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat; supports tags=, severity=, templates=",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the nuclei plugin (template-based vulnerability detection) against a registered target."""
    _run_scan("nuclei", target, option, config, workdir, live)


@scan_app.command("kubernetes")
def scan_kubernetes(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a kubeconfig context name."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports namespaces=, severity="
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the kubernetes plugin (trivy k8s: misconfig/RBAC/image vulnerabilities) against a registered target."""
    _run_scan("kubernetes", target, option, config, workdir, live)


@scan_app.command("sqlmap")
def scan_sqlmap(
    target: str = typer.Option(
        ..., "--target", help="Registered url target with an injectable parameter, e.g. .../item?id=1."
    ),
    option: list[str] = typer.Option(
        [],
        "--option",
        help=(
            "key=value, may repeat; supports risk=, level=, dump=true, dbs=true, etc. "
            "Options that escalate beyond SQLi (os-shell, file-read/write, tamper, ...) "
            "are rejected -- see docs/sqlmap.md."
        ),
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the sqlmap plugin (SQL injection detection/extraction) against a registered target."""
    _run_scan("sqlmap", target, option, config, workdir, live)


@scan_app.command("container")
def scan_container(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a container image reference."
    ),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat; supports severity=, ignore-unfixed=true, scanners=",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the container plugin (trivy image: vulnerabilities/misconfig/secrets) against a registered target."""
    _run_scan("container", target, option, config, workdir, live)


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


@result_app.command("review")
def result_review(
    run_id: str,
    finding_id: str,
    status: FindingStatus,
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Mark a finding as confirmed / false-positive / needs-review."""
    store = _store(workdir)
    try:
        review_finding(store, run_id, finding_id, status)
    except FindingNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"finding '{finding_id}' on run '{run_id}' -> {status.value}")


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


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"


@report_app.command("generate")
def report_generate(
    run_id: str,
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown or html"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Render a report for a run into <workdir>/reports/."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if format == ReportFormat.HTML:
        report_path = workdir / "reports" / f"{run_id}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(html_report.render(record))
    else:
        report_path = workdir / "reports" / f"{run_id}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(markdown.render(record))
    typer.echo(f"wrote {report_path}")


@walkthrough_app.command("generate")
def walkthrough_generate(
    run_ids: list[str] = typer.Argument(
        None, help="Run ids to include, in this order. Give either these or --target, not both."
    ),
    target: Optional[str] = typer.Option(
        None, "--target", help="Include every run recorded against this target, oldest first."
    ),
    model: Optional[str] = typer.Option(
        None, "--model", help="Ollama model name to request from the local llm router."
    ),
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="markdown or html"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Generate a narrative walkthrough connecting multiple runs, via the local LLM.

    Read-only: no run's stored findings/analysis are modified, unlike `analyze`.
    """
    store = _store(workdir)
    adapter = OllamaAdapter(model=model)
    try:
        walkthrough = generate_walkthrough(store, adapter, run_ids or None, target)
    except WalkthroughError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    first_run_id = walkthrough.records[0].run_id
    if format == ReportFormat.HTML:
        report_path = workdir / "reports" / f"walkthrough-{first_run_id}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(walkthrough_report.render_html(walkthrough))
    else:
        report_path = workdir / "reports" / f"walkthrough-{first_run_id}.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(walkthrough_report.render_markdown(walkthrough))
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
    policy = _policy(config)
    plugins = [p.strip() for p in allowed_plugins.split(",") if p.strip()]
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
    """Ask the local LLM router to classify findings and draft a summary for a run."""
    store = _store(workdir)
    adapter = OllamaAdapter(model=model)
    try:
        _, result = run_analysis(store, run_id, adapter)
    except AnalysisError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    if not result.parsed:
        typer.echo(
            "warning: LLM response was not valid JSON; storing it as the summary text only "
            "(no structured findings extracted)",
            err=True,
        )

    typer.echo(result.summary)
    for finding in result.findings:
        typer.echo(f"- [{finding.severity.value}] {finding.title} — {finding.detail}")


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

    web_app_instance = create_app(config=config, workdir=workdir)
    uvicorn.run(web_app_instance, host=host, port=port)


if __name__ == "__main__":
    app()
