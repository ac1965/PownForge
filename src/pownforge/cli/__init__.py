"""Typer entry point (refactor §18 step 3): `pownforge.cli:app` is what
pyproject.toml's `[project.scripts]` and every test that drives the CLI
(`from pownforge.cli import app` / `cli.app`) actually uses -- the only
public name this package promises.

cli.py used to be a single ~2,000-line, 72-command file. It is now this
package: `_shared.py` holds the Typer app objects, composition-root
delegations, and shared imports every command module needs, and each
`<group>.py` below holds one command group's Typer commands, registered
onto the shared apps as a side effect of being imported here. Splitting
this way (rather than, say, one file per command) mirrors how the
sub-apps were already organized (target/engagement/scan/lab/...) and
keeps each file's command count comparable to web/routers/*.py."""

from __future__ import annotations

from pownforge.cli._shared import app
from pownforge.cli import (  # noqa: F401 -- imported for their command-registration side effects
    attack_session,
    audit,
    config,
    engagement,
    evidence,
    lab,
    lab_kind,
    lab_provider,
    operation,
    playbook,
    plugin,
    primitive,
    report,
    result,
    root,
    scan,
    target,
    walkthrough,
    web,
)

__all__ = ["app"]

if __name__ == "__main__":
    app()
