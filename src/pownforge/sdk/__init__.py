"""Public API for writing PownForge plugins outside this repository.

A plugin package subclasses `Plugin` and publishes it under the
`pownforge.plugins` entry point group; see docs/handbook.md §6
("外部プラグイン(Plugin SDK)"). Everything importable from here is the
supported surface -- other `pownforge.*` modules may change without notice.
"""

from pownforge.core.models import PluginMetadata, PluginOption, Severity, Target, TargetKind
from pownforge.core.registry import ENTRY_POINT_GROUP
from pownforge.plugins.base import FindingDict, Plugin, PluginError, PluginExecution

__all__ = [
    "ENTRY_POINT_GROUP",
    "FindingDict",
    "Plugin",
    "PluginError",
    "PluginExecution",
    "PluginMetadata",
    "PluginOption",
    "Severity",
    "Target",
    "TargetKind",
]
