from __future__ import annotations

from pownforge.cli._shared import *  # noqa: F401,F403


def _operations(workdir: Path) -> AttackOperationStore:
    return build_operations(workdir)


@operation_app.command("create")
def operation_create(
    name: str,
    objective: str = typer.Option("", "--objective"),
    engagement: Optional[str] = typer.Option(None, "--engagement"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Create a new attack operation. Never executes anything -- this only
    registers a name to attach actions to via `operation add-action`."""
    try:
        create_operation(_operations(workdir), name, objective, engagement)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"created attack operation '{name}'")


@operation_app.command("show")
def operation_show(name: str, workdir: Path = typer.Option(DEFAULT_WORKDIR)) -> None:
    """Show an attack operation's nodes, edges, actions, and approvals."""
    try:
        operation = _operations(workdir).load(name)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{operation.name}: {operation.objective}")
    typer.echo(
        f"nodes={len(operation.nodes)} edges={len(operation.edges)} "
        f"actions={len(operation.actions)} approvals={len(operation.approvals)}"
    )
    for node in operation.nodes:
        typer.echo(f"  node {node.id}\ttarget={node.target}\tstate={node.state.value}\t{node.label}")
    for edge in operation.edges:
        caps = ",".join(c.value for c in edge.capabilities)
        typer.echo(f"  edge {edge.source} -> {edge.destination}\t{edge.relationship}\t[{caps}]")
    for action in operation.actions:
        typer.echo(f"  action {action.id}\t{action.phase.value}\t{action.kind.value}\t{action.target}\t{action.status.value}")


@operation_app.command("add-node")
def operation_add_node(
    name: str,
    node_id: str,
    target: str = typer.Option(..., "--target"),
    label: str = typer.Option("", "--label"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Add a node (an already-registered target) to an attack operation's graph.

    Purely descriptive bookkeeping -- this never authorizes anything beyond
    what TARGET's own allowed_plugins already permits."""
    try:
        add_node(_operations(workdir), _policy(config), name, node_id, target, label)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"added node '{node_id}' ({target})")


@operation_app.command("add-edge")
def operation_add_edge(
    name: str,
    source: str = typer.Option(..., "--source"),
    destination: str = typer.Option(..., "--destination"),
    capabilities: str = typer.Option(
        "", "--capabilities", help="Comma-separated Capability values; default: network-pivot."
    ),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Add an edge between two graph nodes (SOURCE, DESTINATION already added
    via `add-node`). Purely descriptive: recording an edge grants no
    execution or pivot right on its own -- a PIVOT action still needs its
    own approval and, at `execute` time, an Engagement that both targets
    belong to (see ScopePolicy.authorize_pivot())."""
    caps = [Capability(c.strip()) for c in capabilities.split(",") if c.strip()] or None
    try:
        add_edge(_operations(workdir), _policy(config), name, source, destination, caps)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"added edge '{source}' -> '{destination}'")


@operation_app.command("add-action")
def operation_add_action(
    name: str,
    action_id: str,
    action_name: str,
    target: str = typer.Option(..., "--target"),
    phase: AttackPhase = typer.Option(..., "--phase"),
    kind: ActionKind = typer.Option(ActionKind.SCAN, "--kind"),
    plugin: Optional[str] = typer.Option(None, "--plugin"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Add a candidate action (scan/manual/pivot) to an attack operation."""
    action = Action(id=action_id, name=action_name, phase=phase, kind=kind, target=target, plugin=plugin)
    try:
        add_action(_operations(workdir), _policy(config), name, action)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"added action '{action_id}'")


@operation_app.command("approve")
def operation_approve(
    name: str,
    action_id: str,
    approved_by: str = typer.Option(..., "--approved-by"),
    note: str = typer.Option("", "--note"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
) -> None:
    """Record human approval for an action before it can be executed."""
    try:
        approve_action(_operations(workdir), name, action_id, approved_by, note)
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"approved action '{action_id}'")


@operation_app.command("execute")
def operation_execute(
    name: str,
    action_id: str,
    command: Optional[str] = typer.Option(
        None, "--command", help="MANUAL/PIVOT only: what was actually run (defaults to the action's name)."
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        help="MANUAL/PIVOT only: transcript of the external tool's output. Required for these kinds -- "
        "PownForge never executes them itself, only records what a human already ran "
        "(same as `pownforge result import`).",
    ),
    tool: Optional[str] = typer.Option(None, "--tool", help="MANUAL/PIVOT only: external tool used."),
    tool_version: Optional[str] = typer.Option(None, "--tool-version"),
    returncode: int = typer.Option(0, "--returncode"),
    workdir: Path = typer.Option(DEFAULT_WORKDIR),
    config: Path = typer.Option(DEFAULT_CONFIG),
) -> None:
    """Execute an approved action.

    SCAN actions run through the existing ScanRunner, same as `pownforge
    scan <plugin>`. MANUAL/PIVOT actions never execute anything -- --output
    must already be the transcript of what a human ran with an external
    tool; this only records it (a PIVOT action additionally requires the
    operation to have an --engagement and a graph edge ending at the
    action's target, see `operation add-edge`)."""
    try:
        runner = OperationRunner(
            _policy(config), default_registry(), _store(workdir), _audit(workdir), concurrency=_concurrency(workdir)
        )
        updated = _operations(workdir).update(
            name,
            lambda operation: runner.execute(
                operation,
                action_id,
                manual_command=command,
                manual_output=output,
                manual_tool=tool,
                manual_tool_version=tool_version,
                manual_returncode=returncode,
            ),
        )
    except OperationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"completed action '{action_id}' (run={next(a.run_id for a in updated.actions if a.id == action_id)})")
