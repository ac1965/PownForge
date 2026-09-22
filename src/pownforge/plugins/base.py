from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pownforge.core.models import Target


class PluginError(RuntimeError):
    """Raised when a plugin cannot run or its required tool is missing."""


class Plugin(ABC):
    name: str
    version: str
    description: str
    required_tool: str
    """Name of the external binary this plugin needs (e.g. "nmap"), used in
    error messages so a missing dependency names itself instead of just
    failing generically."""

    @abstractmethod
    def check(self) -> bool:
        """Return True if the plugin's required external tool is available."""

    @abstractmethod
    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        """Return the argv for the external tool, given an already-authorized target."""

    @abstractmethod
    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        """Turn raw tool output into a normalized, JSON-serializable result."""

    def version_command(self) -> list[str] | None:
        """Argv to query the required tool's version (e.g. ["nmap", "--version"]).

        Returns None if the plugin doesn't support version reporting. Like
        build_command, this only returns argv — ScanRunner is the one that
        actually runs it, so plugins never call subprocess themselves."""
        return None
