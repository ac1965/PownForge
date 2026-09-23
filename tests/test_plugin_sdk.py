from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import pownforge.sdk as sdk
from pownforge.core.orchestrator import list_playbooks
from pownforge.core.registry import PluginRegistry, default_registry
from pownforge.sdk import Plugin, PluginError, PluginOption, Target
from pownforge.sdk.testing import assert_findings_shape, assert_plugin_contract

REPO = Path(__file__).resolve().parent.parent


class DemoPlugin(Plugin):
    name = "demo"
    version = "1.0.0"
    description = "demo"
    required_tool = "true"
    options_schema = (
        PluginOption(name="mode", description="mode", default="a", choices=["a", "b"]),
        PluginOption(name="path", description="path", required=True),
    )

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        return ["true"]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {"_findings": [{"title": "x", "severity": "low"}]}


class UndeclaredPlugin(DemoPlugin):
    name = "undeclared"
    options_schema = None


class PassthroughPlugin(DemoPlugin):
    name = "passthrough"
    accepts_extra_options = True


def test_validate_options_accepts_declared_keys_case_insensitive_choices() -> None:
    DemoPlugin().validate_options({"mode": "B", "path": "/x"})


def test_validate_options_rejects_unknown_key() -> None:
    with pytest.raises(PluginError, match="unknown option"):
        DemoPlugin().validate_options({"path": "/x", "bogus": "1"})


def test_validate_options_rejects_missing_required() -> None:
    with pytest.raises(PluginError, match="requires --option path"):
        DemoPlugin().validate_options({})


def test_validate_options_rejects_value_outside_choices() -> None:
    with pytest.raises(PluginError, match="not one of"):
        DemoPlugin().validate_options({"path": "/x", "mode": "c"})


def test_undeclared_schema_is_not_validated() -> None:
    UndeclaredPlugin().validate_options({"anything": "goes"})


def test_accepts_extra_options_still_checks_declared_ones() -> None:
    PassthroughPlugin().validate_options({"path": "/x", "threads": "4"})
    with pytest.raises(PluginError):
        PassthroughPlugin().validate_options({"threads": "4"})


def test_metadata_is_complete() -> None:
    meta = DemoPlugin().metadata()
    assert meta.name == "demo"
    assert meta.tool_available is True
    assert [o.name for o in meta.options or []] == ["mode", "path"]
    assert meta.source == "builtin"
    assert UndeclaredPlugin().metadata().options is None


def test_sdk_testing_helpers_accept_demo_plugin() -> None:
    plugin = DemoPlugin()
    assert_plugin_contract(plugin)
    assert_findings_shape(plugin.normalize(Target(name="t", kind="host", address="h"), "", ""))


def test_assert_findings_shape_rejects_bad_severity() -> None:
    with pytest.raises(AssertionError):
        assert_findings_shape({"_findings": [{"title": "x", "severity": "urgent"}]})


def test_every_builtin_plugin_declares_options() -> None:
    for plugin in default_registry().list():
        if plugin.source == "builtin":
            assert plugin.options_schema is not None, plugin.name


def test_bundled_playbooks_pass_option_validation() -> None:
    registry = default_registry()
    for playbook in list_playbooks(REPO / "config" / "playbooks"):
        for step in playbook.steps:
            registry.get(step.plugin).validate_options(step.options)


def test_sdk_exports() -> None:
    assert set(sdk.__all__) <= set(dir(sdk))
    assert sdk.ENTRY_POINT_GROUP == "pownforge.plugins"


@dataclass
class FakeDist:
    name: str


class FakeEntryPoint:
    def __init__(self, name: str, obj: Any, dist: str = "pownforge-plugin-demo") -> None:
        self.name = name
        self.value = f"demo_pkg:{name}"
        self.dist = FakeDist(dist)
        self._obj = obj

    def load(self) -> Any:
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


def test_load_entry_points_registers_external_plugin_with_source() -> None:
    registry = PluginRegistry()
    registry.load_entry_points([FakeEntryPoint("demo", DemoPlugin)])
    plugin = registry.get("demo")
    assert plugin.source == "pownforge-plugin-demo"
    assert registry.load_errors == []


def test_load_entry_points_never_overrides_existing_plugin() -> None:
    registry = default_registry()
    impostor = type("Impostor", (DemoPlugin,), {"name": "network"})
    registry.load_entry_points([FakeEntryPoint("network", impostor, dist="evil-dist")])
    assert registry.get("network").source == "builtin"
    assert any("already provided by builtin" in e for e in registry.load_errors)


def test_load_entry_points_reports_broken_or_non_plugin_entries() -> None:
    registry = PluginRegistry()
    registry.load_entry_points(
        [
            FakeEntryPoint("broken", ImportError("no module named demo_pkg")),
            FakeEntryPoint("notaplugin", object),
        ]
    )
    assert registry.list() == []
    assert len(registry.load_errors) == 2
