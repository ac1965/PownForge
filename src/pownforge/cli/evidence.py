from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


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


@evidence_app.command("verify-chain")
def evidence_verify_chain(workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Verify the append-only hash chain across every run this workdir's
    EvidenceStore has ever saved (refactor v3 §6). Stronger than
    `evidence verify <run-id>`: that only checks one run's stdout/stderr
    against its own embedded hash (editable together by anyone with file
    access); this also detects a run's on-disk content silently diverging
    from what the chain last recorded for it, and any edit/reorder of the
    chain ledger itself. Still not proof against an adversary willing to
    regenerate the whole chain -- see docs/handbook.md §13."""
    store = _store(workdir)
    result = store.verify_chain()

    if result.entries_checked == 0:
        typer.echo("no chain entries recorded yet (no runs saved since this evidence store started chaining)")
        return

    typer.echo(f"chain entries checked: {result.entries_checked}")
    if result.ok:
        typer.echo("chain verified: no broken links or content mismatches")
        return

    for mismatch in result.mismatches:
        typer.echo(f"  [{mismatch.kind}] run={mismatch.run_id} seq={mismatch.seq}: {mismatch.detail}", err=True)
    typer.echo(f"warning: {len(result.mismatches)} mismatch(es) found in the evidence chain", err=True)
    raise typer.Exit(code=1)
