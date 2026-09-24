"""Target-management Application Service (refactor §18 step 1).

Before this module, `kind=path` address resolution followed by
ScopePolicy.add_target() and a save existed twice: cli.py::target_add and
web/routers/targets.py::add_target each re-implemented it (see the
refactor audit's "業務ロジックがインターフェース層に重複している" finding).
The same "look up the target, mutate it, save under lock" shape was also
repeated across every `lab`/`lab kind`/`lab provider` add/remove command
in both cli.py and web/routers/{lab,lab_kind,lab_provider}.py.

Every function here is a single guarded load-mutate-save
(core.policy.locked_policy) and raises only domain exceptions
(TargetPathError, PolicyError) -- never typer.Exit or HTTPException. CLI
and Web each translate those to their own exit code / HTTP status at the
call site."""

from __future__ import annotations

from pathlib import Path

from pownforge.core.models import Target, TargetKind, resolve_path_target_address
from pownforge.core.policy import locked_policy


def register_target(config: Path, target: Target) -> Target:
    """Resolve TARGET's address (kind=path only -- every other kind is
    registered as given) and register it under ScopePolicy. Returns the
    Target actually stored, whose address may differ from the input for
    kind=path."""
    if target.kind == TargetKind.PATH:
        target = target.model_copy(update={"address": resolve_path_target_address(target.address)})
    with locked_policy(config) as policy:
        policy.add_target(target)
    return target


def remove_target(config: Path, name: str) -> None:
    with locked_policy(config) as policy:
        policy.remove_target(name)


def exclude_target(config: Path, name: str, reason: str | None = None) -> Target:
    with locked_policy(config) as policy:
        target = policy.exclude_target(name, reason)
    return target


def include_target(config: Path, name: str) -> Target:
    with locked_policy(config) as policy:
        target = policy.include_target(name)
    return target
