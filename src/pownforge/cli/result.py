from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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


@result_app.command("import")
def result_import(
    target: str = typer.Option(
        ..., "--target", help="Registered target this was performed against."
    ),
    command: str = typer.Option(
        ..., "--command", help="What was run (e.g. an msfconsole invocation). Recorded as evidence, never executed."
    ),
    output: str = typer.Option(..., "--output", help="Paste of the external tool's output/session transcript."),
    tool: Optional[str] = typer.Option(None, "--tool", help="Name of the external tool used, e.g. 'msfconsole'."),
    tool_version: Optional[str] = typer.Option(None, "--tool-version"),
    returncode: int = typer.Option(0, "--returncode"),
    engagement: Optional[str] = typer.Option(
        None,
        "--engagement",
        help="Record this as a pivot step: TARGET was reached via --via, as part of this Engagement. "
        "Requires --via.",
    ),
    via: Optional[str] = typer.Option(
        None, "--via", help="The target TARGET was reached from/via. Requires --engagement."
    ),
    phase: Optional[KillChainPhase] = typer.Option(
        None,
        "--phase",
        help="Where this step sits in the attack chain (discovery/vuln-confirm/exploit/"
        "initial-access/privilege-escalation/lateral-movement/persistence/impact). Purely "
        "descriptive for reports/walkthroughs -- PownForge never executes anything based on it.",
    ),
    artifact: list[Path] = typer.Option(
        [],
        "--artifact",
        help="File to attach as proof (pcap, transcript, screenshot). May repeat. Copied into "
        "the evidence store and hashed at import time.",
    ),
    cve: list[str] = typer.Option(
        [], "--cve", help="CVE id this step relates to, e.g. CVE-2021-44228. May repeat."
    ),
    finding_title: Optional[str] = typer.Option(
        None,
        "--finding-title",
        help="Also attach a Finding (source=manual) to this run in the same command, instead of a "
        "separate `result add-finding` call. Like every Finding it starts at needs-review -- "
        "`result review` still has to be run explicitly to confirm it.",
    ),
    finding_severity: Severity = typer.Option(Severity.INFO, "--finding-severity", help="Only used with --finding-title."),
    finding_detail: str = typer.Option("", "--finding-detail", help="Only used with --finding-title."),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Record evidence for a step performed manually with an external tool
    (e.g. Metasploit) against a registered target -- PownForge does not run
    COMMAND itself. The target must allow the 'manual' plugin name (or have
    an empty allowed_plugins list). See docs/handbook.md §13."""
    policy = _policy(config)
    store = _store(workdir)
    try:
        record = import_manual_run(
            policy,
            store,
            target,
            command,
            output,
            tool=tool,
            tool_version=tool_version,
            returncode=returncode,
            audit=_audit(workdir),
            engagement=engagement,
            via_target=via,
            kill_chain_phase=phase,
            artifacts=list(artifact) or None,
            cves=list(cve) or None,
        )
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except PolicyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"run {record.run_id} recorded (target={record.target}, plugin=manual)")
    for art in record.artifacts:
        typer.echo(f"  artifact: {art.description} -> {art.path} (sha256 {art.sha256})")
    if finding_title:
        _, finding = add_finding(store, record.run_id, finding_title, finding_severity, finding_detail)
        typer.echo(f"finding '{finding.finding_id}' added to run '{record.run_id}' (status=needs-review)")


@result_app.command("tag")
def result_tag(
    run_id: str,
    cve: list[str] = typer.Option([], "--cve", help="CVE id to add (or remove with --remove). May repeat."),
    remove: bool = typer.Option(False, "--remove", help="Remove the given CVE ids instead of adding."),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Add or remove CVE tags on an existing run (scan or manual import). Tags
    are correlation labels for `report engagement`'s CVE exposure matrix."""
    store = _store(workdir)
    try:
        record = store.load(run_id)
    except FileNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if not cve:
        typer.echo("error: pass at least one --cve", err=True)
        raise typer.Exit(code=1)
    if remove:
        record.cves = [c for c in record.cves if c not in cve]
    else:
        for c in cve:
            if c not in record.cves:
                record.cves.append(c)
    store.save(record)
    typer.echo(f"run {run_id} cves: {', '.join(record.cves) or '(none)'}")


@result_app.command("add-finding")
def result_add_finding(
    run_id: str,
    title: str = typer.Option(..., "--title"),
    severity: Severity = typer.Option(Severity.INFO, "--severity"),
    detail: str = typer.Option("", "--detail"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Attach a human-observed finding (source="manual") to an existing run."""
    store = _store(workdir)
    try:
        _, finding = add_finding(store, run_id, title, severity, detail)
    except FindingNotFoundError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"finding '{finding.finding_id}' added to run '{run_id}' (status=needs-review)")


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
