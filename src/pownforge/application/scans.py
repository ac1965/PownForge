"""Scan-execution Application Service (refactor §18 step 1, extending the
target Application Service to a second use case: "run a plugin against a
registered target").

Before this module, cli.py::_run_scan built a ScanRunner itself --
policy/registry/store/audit/concurrency, five separate composition-root
calls plus the ScanRunner() constructor -- every time any of the 15 `scan
<plugin>` commands ran (the exact CLI-holds-business-logic shape §18
warns against). web/deps.py::get_runner() already builds the same thing
through FastAPI's DI, itself wired to the composition root (§18 step 2);
this module gives CLI the same single call.

Deliberately Typer-agnostic: PolicyError/RunnerError/PluginError/
RegistryError (all already domain exceptions -- see core/runner.py)
propagate as-is. CLI translates them to its own exit code at the call
site, same as every other Application Service function."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pownforge.application.context import (
    build_audit,
    build_concurrency,
    build_policy,
    build_registry,
    build_store,
)
from pownforge.core.models import RunRecord
from pownforge.core.runner import OnLine, ScanRunner


def run_scan(
    config: Path,
    workdir: Path,
    plugin_name: str,
    target_name: str,
    options: dict[str, Any],
    on_line: OnLine | None = None,
) -> RunRecord:
    """Build a ScanRunner from the composition root and run PLUGIN_NAME
    against TARGET_NAME with OPTIONS -- the one place "run a plugin scan"
    happens for the CLI's synchronous `scan <plugin>` commands."""
    runner = ScanRunner(
        policy=build_policy(config),
        registry=build_registry(),
        store=build_store(workdir),
        audit=build_audit(workdir),
        concurrency=build_concurrency(workdir),
    )
    return runner.run(target_name, plugin_name, options, on_line=on_line)
