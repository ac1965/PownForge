import pytest

from pownforge.core.registry import PluginRegistry, RegistryError, default_registry


def test_default_registry_has_network_and_web() -> None:
    registry = default_registry()
    names = {plugin.name for plugin in registry.list()}
    assert {"network", "web"} <= names


def test_get_unknown_plugin_raises() -> None:
    registry = PluginRegistry()
    with pytest.raises(RegistryError):
        registry.get("nope")
