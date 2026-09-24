from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, TypedDict

from pownforge.core.models import PluginMetadata, PluginOption, Target, TargetKind


class PluginError(RuntimeError):
    """Raised when a plugin cannot run or its required tool is missing."""


class PluginExecution:
    """Per-run scratch space for one build_command()/normalize() pair.

    PluginRegistry keeps exactly one Plugin instance per name, shared by
    every run of that plugin (see core/registry.py) -- concurrent scans of
    the same plugin (e.g. two Web UI requests running 'network' against two
    targets at once) share that instance. Plugins that stashed a temp path
    on `self` between build_command() and normalize() (self._xml_path and
    friends) raced under that sharing: two concurrent runs could clobber
    each other's path.

    ScanRunner creates a fresh PluginExecution, backed by a unique temp
    directory, for every run and passes the SAME instance to both
    build_command() and normalize() for that run -- so a plugin calls
    `execution.path("output.xml")` in each and always gets the same Path
    back *for that run*, without ever writing to `self`. Two concurrent
    runs of the same Plugin instance get two different PluginExecution
    objects with two different directories, so nothing can collide. See
    refactor §4.1."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self.data: dict[str, Any] = {}
        """Scratch storage for small per-run values that aren't worth a temp
        file (e.g. the exact URL/method build_command() constructed, needed
        again by normalize() -- see ApiPlugin/IdentityPlugin). Same
        per-execution isolation as `path()`, just for values instead of
        files."""

    def path(self, filename: str) -> Path:
        """A path under this execution's own scratch directory. Stable
        across repeated calls with the same FILENAME within one run;
        never shared with any other run."""
        return self.workdir / filename


class FindingDict(TypedDict, total=False):
    """One entry of normalize()'s optional "_findings" list. `title` is
    required in practice; severity falls back to "info" when missing or
    invalid (core/finding_utils.py)."""

    title: str
    severity: str
    detail: str


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

    options_schema: ClassVar[tuple[PluginOption, ...] | None] = None
    """The `--option` keys this plugin reads. When declared, ScanRunner calls
    validate_options() before build_command(), so an unknown key, a missing
    required key, or a value outside `choices` fails before anything runs.
    None = undeclared (not validated), e.g. an external plugin that predates
    the schema."""

    accepts_extra_options: ClassVar[bool] = False
    """True for a plugin that passes undeclared keys through to its tool
    (sqlmap), so validate_options() only checks the declared ones."""

    host_list_option: ClassVar[str | None] = None
    """Declares which options_schema key (if any) holds a comma-separated
    list of ADDITIONAL, already-registered Target names -- not raw
    hostnames/URLs -- that this plugin scans alongside its primary target
    (e.g. httpprobe's `hosts`, for triaging recon's output: a discovered
    subdomain is not itself authorized scope, so each candidate must be its
    own registered Target). None (default, every plugin except httpprobe)
    means no such option exists.

    When set, ScanRunner authorizes every name in this option via the same
    ScopePolicy.authorize() call the primary target already goes through
    (same audit-on-denial behavior), before build_command() runs, and
    replaces the option's value with the comma-separated *addresses* of
    only the names that passed -- a rejected name is excluded, recorded
    (never silently dropped), and never reaches the plugin. This is the one
    place a Plugin's options can name additional scope at all; plugins
    otherwise have no path to ScopePolicy (see core/runner.py)."""

    source: str = "builtin"
    """Set by the registry to the distribution name of an external plugin."""

    @abstractmethod
    def check(self) -> bool:
        """Return True if the plugin's required external tool is available."""

    @abstractmethod
    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        """Return the argv for the external tool, given an already-authorized
        target. EXECUTION is this run's scratch space (see PluginExecution) --
        use `execution.path(name)` for any temp file the command needs to
        write to (an nmap -oX target, an ffuf -o target, ...) instead of
        storing it on `self`, which is shared across concurrent runs."""

    @abstractmethod
    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        """Turn raw tool output into a normalized, JSON-serializable result.
        EXECUTION is the SAME PluginExecution passed to build_command() for
        this run -- `execution.path(name)` returns the identical Path, so a
        temp file build_command() had the tool write to is found the same
        way here, again without touching `self`.

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

    def validate_options(self, options: dict[str, Any]) -> None:
        """Raise PluginError if OPTIONS don't match options_schema. A no-op
        when the plugin declares no schema."""
        if self.options_schema is None:
            return
        declared = {opt.name: opt for opt in self.options_schema}
        if not self.accepts_extra_options:
            unknown = sorted(set(options) - set(declared))
            if unknown:
                known = ", ".join(sorted(declared)) or "(none)"
                raise PluginError(
                    f"{self.name} plugin: unknown option(s) {', '.join(unknown)}; accepted: {known}"
                )
        for opt in self.options_schema:
            value = options.get(opt.name)
            if value is None or value == "":
                if opt.required:
                    raise PluginError(f"{self.name} plugin requires --option {opt.name}=<value>")
                continue
            if opt.choices is not None and str(value).lower() not in {c.lower() for c in opt.choices}:
                raise PluginError(
                    f"{self.name} plugin: option {opt.name}={value} is not one of "
                    f"{', '.join(opt.choices)}"
                )

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            version=self.version,
            description=self.description,
            required_tool=self.required_tool,
            expected_kind=self.expected_kind,
            kind_hint=self.kind_hint,
            options=list(self.options_schema) if self.options_schema is not None else None,
            accepts_extra_options=self.accepts_extra_options,
            tool_available=self.check(),
            source=self.source,
        )
