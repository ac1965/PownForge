from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pownforge.core.models import Target, TargetKind


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

    expected_kind: TargetKind | None = None
    """Declares which Target.kind this plugin's address format assumes (None
    = no constraint, e.g. NetworkPlugin works with either host or url). Purely
    additive metadata plus the one check every url/host-specific plugin was
    already hand-rolling ad hoc -- see require_kind() and
    docs/handbook.md §2 (全体アーキテクチャ)."""

    kind_hint: str | None = None
    """Optional extra guidance appended to require_kind()'s error message,
    for a plugin whose address format needs more than "host" or "url" to
    explain (e.g. SqlmapPlugin's "include an injectable parameter")."""

    @abstractmethod
    def check(self) -> bool:
        """Return True if the plugin's required external tool is available."""

    @abstractmethod
    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        """Return the argv for the external tool, given an already-authorized target."""

    @abstractmethod
    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        """Turn raw tool output into a normalized, JSON-serializable result.

        May include an "_findings" key: a list of {"title", "severity",
        "detail"} dicts for tool-native matches (e.g. nuclei template hits).
        ScanRunner pops that key and turns it into real Finding objects
        (source="tool", status defaults to needs-review like any other
        finding). Plugins that don't set it are unaffected."""

    def version_command(self) -> list[str] | None:
        """Argv to query the required tool's version (e.g. ["nmap", "--version"]).

        Returns None if the plugin doesn't support version reporting. Like
        build_command, this only returns argv — ScanRunner is the one that
        actually runs it, so plugins never call subprocess themselves."""
        return None

    def parse_version_output(self, stdout: str, stderr: str) -> str | None:
        """Extract a human-readable version string from version_command()'s
        captured output. Default: first non-empty line of stdout, falling
        back to stderr. Override this when the tool logs other lines (a
        warning, a banner) ahead of the actual version on the same stream —
        nuclei always does this, for example."""
        output = (stdout or stderr or "").strip()
        if not output:
            return None
        return output.splitlines()[0]

    def require_kind(self, target: Target) -> None:
        """Raise PluginError if TARGET.kind doesn't match expected_kind.
        A no-op when expected_kind is None. Call this first thing in
        build_command() -- it replaces each plugin hand-rolling its own
        ad hoc `if target.kind != ...` check."""
        if self.expected_kind is not None and target.kind != self.expected_kind:
            hint = f" {self.kind_hint}" if self.kind_hint else ""
            raise PluginError(
                f"{self.name} plugin requires a {self.expected_kind.value} target "
                f"(got {target.kind.value}); register with --kind {self.expected_kind.value}.{hint}"
            )
