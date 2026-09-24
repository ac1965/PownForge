from __future__ import annotations

from pownforge.application import scans as scan_service
from pownforge.cli._shared import *  # noqa: F401,F403


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

    on_line = (lambda line: typer.echo(f"| {line}")) if live else None
    try:
        record = scan_service.run_scan(config, workdir, plugin_name, target, options, on_line=on_line)
    except (PolicyError, RunnerError, PluginError, RegistryError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"run {record.run_id} completed (exit={record.evidence.returncode})")
    # A tool exiting 0 doesn't mean it found what you expected -- e.g. nmap
    # exits 0 on "0 hosts up" whether that's a genuinely empty result or a
    # DNS resolution failure. Flag non-empty stderr so a run that silently
    # did nothing useful doesn't look identical to a real result.
    if record.output.get("raw_stderr"):
        typer.echo(
            f"note: the tool wrote to stderr -- run `pownforge result show {record.run_id}` "
            "before assuming this run found what you expected",
            err=True,
        )


@scan_app.command("run")
def scan_run(
    plugin: str = typer.Argument(..., help="Plugin name (see `pownforge plugin list`), incl. external ones."),
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat (see `pownforge plugin info <plugin>`)"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run any registered plugin by name against a registered target."""
    _run_scan(plugin, target, option, config, workdir, live)


@scan_app.command("recon")
def scan_recon(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a bare domain name, e.g. example.com."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports sources=, exclude_sources="
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the recon plugin (subfinder: passive subdomain discovery from public sources) against a registered target."""
    _run_scan("recon", target, option, config, workdir, live)


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


@scan_app.command("api")
def scan_api(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat: path=/..., method=GET|HEAD|OPTIONS, timeout=<s>"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the api plugin (one curl request, passive header checks) against a registered url target."""
    _run_scan("api", target, option, config, workdir, live)


@scan_app.command("identity")
def scan_identity(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat: document=openid-configuration|oauth-authorization-server, timeout=<s>",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the identity plugin (fetch the public OIDC/OAuth discovery document once)."""
    _run_scan("identity", target, option, config, workdir, live)


@scan_app.command("httpx")
def scan_httpx(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat: paths=/,/admin,... paths_file=<file> timeout=<s>"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the httpx plugin (bulk HTTP probe of paths on one registered url target)."""
    _run_scan("httpx", target, option, config, workdir, live)


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


@scan_app.command("kubernetes-audit")
def scan_kubernetes_audit(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a kubeconfig context name."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports namespaces= (trivy vulnerability scan scope)"
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """One-shot RBAC/Pod Security/Network/Image attack-chain audit (kubectl + trivy k8s) against a registered target."""
    _run_scan("kubernetes-audit", target, option, config, workdir, live)


@scan_app.command("kube-bench")
def scan_kube_bench(
    target: str = typer.Option(
        ..., "--target", help="Registered target whose address is a kubeconfig context name."
    ),
    option: list[str] = typer.Option(
        [], "--option", help="key=value, may repeat; supports image= (default: pownforge-pownforge:latest), timeout="
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run kube-bench (CIS Kubernetes Benchmark) as an in-cluster Job against a registered target."""
    _run_scan("kube-bench", target, option, config, workdir, live)


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
            "are rejected -- see docs/handbook.md #6."
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


@scan_app.command("vulncheck")
def scan_vulncheck(
    target: str = typer.Option(..., "--target"),
    option: list[str] = typer.Option(
        [],
        "--option",
        help="key=value, may repeat; requires script=<name> (see `pownforge plugin info vulncheck`), optional port=",
    ),
    live: bool = typer.Option(
        False, "--live", help="Stream the underlying tool's stdout line-by-line as it runs."
    ),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run the vulncheck plugin (a single, allowlisted nmap NSE 'vuln safe' script that verifies one known CVE) against a registered target."""
    _run_scan("vulncheck", target, option, config, workdir, live)
