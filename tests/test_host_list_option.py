"""Plugin.host_list_option / ScanRunner._resolve_host_list_option: lets a
plugin (currently only `httpprobe`) declare an option that names OTHER
already-registered Targets, each individually re-authorized through the
same ScopePolicy.authorize() the primary target already goes through --
see plugins/base.py and plugin-additions instructions §7.1."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import ScopePolicy
from pownforge.core.registry import PluginRegistry
from pownforge.core.runner import ScanRunner
from pownforge.evidence.audit import AuditStore
from pownforge.evidence.store import EvidenceStore
from pownforge.plugins.base import Plugin, PluginExecution


class _HostListPlugin(Plugin):
    """Test double: records exactly what it was handed, so tests can assert
    on the resolved `hosts` option and the excluded_hosts execution.data
    without any real subprocess involved."""

    name = "host-list-echo"
    version = "0.0.1"
    description = "test double for Plugin.host_list_option"
    required_tool = "true"
    host_list_option = "hosts"

    def check(self) -> bool:
        return True

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        execution.data["seen_hosts_option"] = options.get("hosts", "")
        return ["true"]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        return {
            "seen_hosts_option": execution.data.get("seen_hosts_option", ""),
            "excluded_hosts": execution.data.get("excluded_hosts", []),
        }


def _runner(tmp_path: Path) -> tuple[ScanRunner, ScopePolicy, AuditStore]:
    policy = ScopePolicy(
        targets={
            "anchor": Target(name="anchor", kind=TargetKind.HOST, address="anchor.example"),
            "sub-a": Target(name="sub-a", kind=TargetKind.URL, address="https://a.example"),
            "sub-b": Target(name="sub-b", kind=TargetKind.URL, address="https://b.example"),
            # Registered, but not allowed to run this specific plugin.
            "sub-c-restricted": Target(
                name="sub-c-restricted",
                kind=TargetKind.URL,
                address="https://c.example",
                allowed_plugins=["some-other-plugin"],
            ),
        }
    )
    registry = PluginRegistry()
    registry.register(_HostListPlugin())
    store = EvidenceStore(tmp_path / "runs")
    audit = AuditStore(tmp_path / "violations")
    return ScanRunner(policy=policy, registry=registry, store=store, audit=audit), policy, audit


def test_all_authorized_hosts_are_resolved_to_addresses(tmp_path: Path) -> None:
    runner, _, _ = _runner(tmp_path)
    record = runner.run("anchor", "host-list-echo", {"hosts": "sub-a,sub-b"})

    assert record.output["seen_hosts_option"] == "https://a.example,https://b.example"
    assert record.output["excluded_hosts"] == []


def test_an_unregistered_host_name_is_excluded_and_recorded(tmp_path: Path) -> None:
    runner, _, audit = _runner(tmp_path)
    record = runner.run("anchor", "host-list-echo", {"hosts": "sub-a,not-a-registered-target"})

    assert record.output["seen_hosts_option"] == "https://a.example"
    excluded = record.output["excluded_hosts"]
    assert len(excluded) == 1
    assert excluded[0]["name"] == "not-a-registered-target"

    violations = audit.list()
    assert any(v.target == "not-a-registered-target" for v in violations)


def test_a_host_not_allowed_for_this_plugin_is_excluded_and_recorded(tmp_path: Path) -> None:
    runner, _, audit = _runner(tmp_path)
    record = runner.run("anchor", "host-list-echo", {"hosts": "sub-a,sub-c-restricted"})

    assert record.output["seen_hosts_option"] == "https://a.example"
    excluded = record.output["excluded_hosts"]
    assert len(excluded) == 1
    assert excluded[0]["name"] == "sub-c-restricted"
    assert "not authorized" in excluded[0]["reason"]

    violations = audit.list()
    assert any(v.target == "sub-c-restricted" for v in violations)


def test_out_of_scope_host_is_never_contacted_only_recorded(tmp_path: Path) -> None:
    """The excluded name never reaches build_command() as something to
    probe -- it only shows up in excluded_hosts, proving it was filtered
    out before the plugin saw it, not silently included."""
    runner, _, _ = _runner(tmp_path)
    record = runner.run("anchor", "host-list-echo", {"hosts": "not-a-registered-target"})

    assert record.output["seen_hosts_option"] == ""
    assert record.output["excluded_hosts"][0]["name"] == "not-a-registered-target"


def test_empty_hosts_option_resolves_to_empty_with_no_exclusions(tmp_path: Path) -> None:
    runner, _, _ = _runner(tmp_path)
    record = runner.run("anchor", "host-list-echo", {})
    assert record.output["seen_hosts_option"] == ""
    assert record.output["excluded_hosts"] == []


def test_plugins_without_host_list_option_are_unaffected(tmp_path: Path) -> None:
    """Every plugin except httpprobe leaves Plugin.host_list_option at its
    default None -- ScanRunner must not touch their options at all."""

    class _PlainPlugin(Plugin):
        name = "plain"
        version = "0.0.1"
        description = "no host_list_option"
        required_tool = "true"

        def check(self) -> bool:
            return True

        def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
            execution.data["seen_options"] = dict(options)
            return ["true"]

        def normalize(
            self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
        ) -> dict[str, Any]:
            return {"seen_options": execution.data.get("seen_options", {})}

    policy = ScopePolicy(targets={"anchor": Target(name="anchor", kind=TargetKind.HOST, address="anchor.example")})
    registry = PluginRegistry()
    registry.register(_PlainPlugin())
    runner = ScanRunner(policy=policy, registry=registry, store=EvidenceStore(tmp_path / "runs"))

    record = runner.run("anchor", "plain", {"hosts": "sub-a,sub-b", "other": "x"})
    assert record.output["seen_options"] == {"hosts": "sub-a,sub-b", "other": "x"}
