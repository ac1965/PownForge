from __future__ import annotations

from pownforge.core.models import TargetKind
from pownforge.plugins.base import Plugin


def assert_plugin_contract(plugin: Plugin) -> None:
    """Assert the base `Plugin` ABC contract every plugin must satisfy.

    Not a replacement for a plugin's own specific tests (build_command
    output, normalize() parsing, etc.) -- those still belong in
    test_plugins.py. This only checks the generic shape shared by all
    plugins, so adding a new plugin can't accidentally skip it."""
    assert plugin.name, "Plugin.name must be a non-empty string"
    assert plugin.version, "Plugin.version must be a non-empty string"
    assert plugin.description, "Plugin.description must be a non-empty string"
    assert plugin.required_tool, "Plugin.required_tool must be a non-empty string"
    assert isinstance(plugin.check(), bool)

    version_command = plugin.version_command()
    assert version_command is None or (
        isinstance(version_command, list) and all(isinstance(part, str) for part in version_command)
    )

    assert plugin.expected_kind is None or isinstance(plugin.expected_kind, TargetKind)
    assert plugin.kind_hint is None or isinstance(plugin.kind_hint, str)
