from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


@playbook_app.command("list")
def playbook_list(playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir")) -> None:
    """List available playbooks."""
    playbooks = list_playbooks(playbooks_dir)
    if not playbooks:
        typer.echo(f"no playbooks found in {playbooks_dir}")
        raise typer.Exit()
    for playbook in playbooks:
        typer.echo(f"{playbook.name}\t{len(playbook.steps)} steps\t{playbook.description}")


@playbook_app.command("show")
def playbook_show(
    name: str, playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir")
) -> None:
    """Show a playbook's steps in order."""
    try:
        playbook = resolve_playbook(playbooks_dir, name)
    except PlaybookError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{playbook.name}: {playbook.description}")
    for i, step in enumerate(playbook.steps, start=1):
        options = ", ".join(f"{k}={v}" for k, v in step.options.items())
        line = f"  {i}. {step.plugin}" + (f" ({options})" if options else "")
        if step.when is not None:
            line += f" [when: step {step.when.after_step} has finding >= {step.when.min_severity.value}]"
        typer.echo(line)


@playbook_app.command("run")
def playbook_run(
    name: str,
    target: str = typer.Option(..., "--target"),
    playbooks_dir: Path = typer.Option(DEFAULT_PLAYBOOKS_DIR, "--playbooks-dir"),
    config: Path = typer.Option(DEFAULT_CONFIG),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Run every step of a playbook against a registered target, in order.

    Each step goes through the same ScopePolicy authorization and evidence
    pipeline as `pownforge scan <plugin>` -- a playbook grants no execution
    right beyond what the target's own --allowed-plugins already permits
    for each step. A failing step does not stop the playbook; failures are
    still reported, never silently dropped."""
    try:
        playbook = resolve_playbook(playbooks_dir, name)
    except PlaybookError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    policy = _policy(config)
    registry = default_registry()
    store = _store(workdir)

    def on_step(index: int, total: int, step) -> None:  # noqa: ANN001
        typer.echo(f"[{index}/{total}] running {step.plugin}...")

    results = run_playbook(
        playbook,
        target,
        policy,
        registry,
        store,
        audit=_audit(workdir),
        on_step=on_step,
        concurrency=_concurrency(workdir),
    )

    run_ids: list[str] = []
    failures = 0
    skipped = 0
    for index, result in enumerate(results, start=1):
        if result.skipped:
            skipped += 1
            assert result.step.when is not None
            typer.echo(
                f"[{index}/{len(results)}] {result.step.plugin}: SKIPPED "
                f"(condition not met: step {result.step.when.after_step} needed a finding "
                f">= {result.step.when.min_severity.value})"
            )
        elif result.record is not None:
            run_ids.append(result.record.run_id)
            typer.echo(
                f"[{index}/{len(results)}] {result.step.plugin}: run {result.record.run_id} "
                f"completed (exit={result.record.evidence.returncode})"
            )
            if result.record.output.get("raw_stderr"):
                typer.echo(
                    f"  note: the tool wrote to stderr -- run `pownforge result show "
                    f"{result.record.run_id}` before assuming this step found what you expected",
                    err=True,
                )
        else:
            failures += 1
            typer.echo(f"[{index}/{len(results)}] {result.step.plugin}: FAILED -- {result.error}", err=True)

    typer.echo(
        f"playbook '{name}' finished: {len(results) - failures - skipped}/{len(results)} steps "
        f"succeeded ({skipped} skipped, {failures} failed)"
    )
    if run_ids:
        typer.echo(f"next: pownforge walkthrough generate {' '.join(run_ids)}")
    if failures:
        raise typer.Exit(code=1)
