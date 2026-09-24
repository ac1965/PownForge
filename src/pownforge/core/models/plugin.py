from __future__ import annotations

from pydantic import BaseModel

from pownforge.core.models.target import TargetKind


class PluginOption(BaseModel):
    """One `--option key=value` a plugin accepts. Values always arrive as
    strings (CLI/Web/playbook YAML), so there is no type field."""

    name: str
    description: str
    required: bool = False
    default: str | None = None
    choices: list[str] | None = None
    """Case-insensitive allowed values; None = free-form."""


class PluginMetadata(BaseModel):
    name: str
    version: str
    description: str
    required_tool: str
    expected_kind: TargetKind | None = None
    kind_hint: str | None = None
    options: list[PluginOption] | None = None
    """None = the plugin declares no option schema (not validated)."""
    accepts_extra_options: bool = False
    tool_available: bool
    source: str = "builtin"
    """"builtin", or the distribution name an external plugin came from."""
