from __future__ import annotations

from pownforge.plugins.base import Plugin
from pownforge.plugins.container import ContainerPlugin
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


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Plugin:
        try:
            return self._plugins[name]
        except KeyError as exc:
            raise RegistryError(f"unknown plugin '{name}'") from exc

    def list(self) -> list[Plugin]:
        return list(self._plugins.values())


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
    return registry
