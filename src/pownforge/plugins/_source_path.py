"""Shared helper for `path`-kind targets (source code / IaC directories),
used by the `secrets`/`sast`/`iac` plugins. Mirrors require_same_origin()
(plugins/api.py), which does the equivalent re-check for `url`-kind targets.
"""

from __future__ import annotations

from pathlib import Path

from pownforge.plugins.base import PluginError


def resolve_registered_directory(plugin_name: str, address: str) -> Path:
    """Re-resolve ADDRESS (a `path`-kind Target.address, already an absolute
    symlink-resolved directory as stored by
    core.models.resolve_path_target_address() at `target add` time) and
    verify it still points to the exact same real directory.

    Defends against the directory being replaced with a symlink pointing
    elsewhere between registration and this scan (TOCTOU) -- the plugin
    would otherwise happily hand the tool a path that now escapes the
    registered/authorized directory."""
    path = Path(address)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise PluginError(f"{plugin_name} plugin: target path '{address}' no longer exists: {exc}") from exc
    if not resolved.is_dir():
        raise PluginError(f"{plugin_name} plugin: target path '{address}' is not a directory")
    if str(resolved) != address:
        raise PluginError(
            f"{plugin_name} plugin: target path '{address}' now resolves to a different "
            f"real path ('{resolved}') -- possible symlink swap since registration; "
            "re-register the target with `pownforge target add`"
        )
    return resolved
