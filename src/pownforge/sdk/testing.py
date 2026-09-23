"""Assertions a plugin's own test suite can run: `assert_plugin_contract(MyPlugin())`."""

from __future__ import annotations

from pownforge.core.models import Severity, TargetKind
from pownforge.plugins.base import Plugin


def assert_plugin_contract(plugin: Plugin) -> None:
    """Assert the generic shape every plugin must satisfy. Not a substitute
    for a plugin's own build_command()/normalize() tests."""
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

    if plugin.options_schema is not None:
        names = [opt.name for opt in plugin.options_schema]
        assert len(names) == len(set(names)), f"{plugin.name}: duplicate option names {names}"
        for opt in plugin.options_schema:
            assert opt.description, f"{plugin.name}: option {opt.name} needs a description"
            if opt.choices is not None and opt.default is not None:
                assert opt.default.lower() in {c.lower() for c in opt.choices}, (
                    f"{plugin.name}: default {opt.default!r} of option {opt.name} is not in its choices"
                )
            assert not (opt.required and opt.default is not None), (
                f"{plugin.name}: option {opt.name} is required but also has a default"
            )

    metadata = plugin.metadata()
    assert metadata.name == plugin.name


def assert_findings_shape(result: dict) -> None:
    """Assert normalize()'s optional "_findings" list follows the FindingDict convention."""
    findings = result.get("_findings", [])
    assert isinstance(findings, list), "_findings must be a list"
    valid = {s.value for s in Severity}
    for finding in findings:
        assert isinstance(finding, dict) and finding.get("title"), f"finding needs a title: {finding!r}"
        severity = finding.get("severity")
        assert severity is None or severity in valid, f"unknown severity {severity!r}"
