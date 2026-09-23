from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from typing import Iterable

from pownforge.plugins.api import ApiPlugin
from pownforge.plugins.base import Plugin
from pownforge.plugins.container import ContainerPlugin
from pownforge.plugins.identity import IdentityPlugin
from pownforge.plugins.kube_bench import KubeBenchPlugin
from pownforge.plugins.kubernetes import KubernetesPlugin
from pownforge.plugins.kubernetes_audit import KubernetesAuditPlugin
from pownforge.plugins.network import NetworkPlugin
from pownforge.plugins.nuclei import NucleiPlugin
from pownforge.plugins.recon import ReconPlugin
from pownforge.plugins.sqlmap import SqlmapPlugin
from pownforge.plugins.vulncheck import VulncheckPlugin
from pownforge.plugins.web import WebPlugin


class RegistryError(RuntimeError):
    """Raised for unknown or misconfigured plugins."""


ENTRY_POINT_GROUP = "pownforge.plugins"


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}
        self.load_errors: list[str] = []
        """External plugins that were skipped, with the reason. A broken or
        conflicting third-party package must not take the whole CLI down."""

    def register(self, plugin: Plugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Plugin:
        try:
            return self._plugins[name]
        except KeyError as exc:
            raise RegistryError(f"unknown plugin '{name}'") from exc

    def list(self) -> list[Plugin]:
        return list(self._plugins.values())

    def load_entry_points(self, eps: Iterable[EntryPoint] | None = None) -> None:
        """Register external plugins published under the `pownforge.plugins`
        entry point group. Each entry point must resolve to a Plugin subclass.
        A name already taken (e.g. a built-in) is never overridden."""
        if eps is None:
            eps = entry_points(group=ENTRY_POINT_GROUP)
        for ep in eps:
            dist = ep.dist.name if ep.dist is not None else ep.value
            try:
                cls = ep.load()
                if not (isinstance(cls, type) and issubclass(cls, Plugin)):
                    raise TypeError(f"{ep.value} is not a pownforge Plugin subclass")
                plugin = cls()
            except Exception as exc:  # noqa: BLE001 -- third-party code, report and continue
                self.load_errors.append(f"{ep.name} ({dist}): {exc}")
                continue
            if plugin.name in self._plugins:
                existing = self._plugins[plugin.name].source
                self.load_errors.append(
                    f"{ep.name} ({dist}): plugin name '{plugin.name}' is already provided by {existing}"
                )
                continue
            plugin.source = dist
            self._plugins[plugin.name] = plugin


def default_registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(ReconPlugin())
    registry.register(NetworkPlugin())
    registry.register(WebPlugin())
    registry.register(NucleiPlugin())
    registry.register(KubernetesPlugin())
    registry.register(KubernetesAuditPlugin())
    registry.register(KubeBenchPlugin())
    registry.register(SqlmapPlugin())
    registry.register(ContainerPlugin())
    registry.register(VulncheckPlugin())
    registry.register(ApiPlugin())
    registry.register(IdentityPlugin())
    registry.load_entry_points()
    return registry
