from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class TargetKind(str, Enum):
    HOST = "host"
    URL = "url"
    # A local filesystem directory (source code checkout, IaC manifests).
    # `address` holds an absolute, symlink-resolved path -- see
    # resolve_path_target_address() and docs/handbook.md §6.
    PATH = "path"


class TargetType(str, Enum):
    """Assessment domain of a target, independent of `kind` (which only
    describes the address format). Purely descriptive: it groups/labels
    targets for reporting and the target list, and does not itself gate
    which plugins may run (that remains `allowed_plugins`). For a
    `kubernetes` target, `address` holds a kubeconfig context name rather
    than a host/URL. For a `container` target, `address` holds an image
    reference (e.g. "nginx:1.25"). See docs/handbook.md §6 (プラグイン)."""

    NETWORK = "network"
    WEB = "web"
    API = "api"
    KUBERNETES = "kubernetes"
    CONTAINER = "container"
    SOURCE_CODE = "source-code"


class TargetPathError(ValueError):
    """Raised when a `path`-kind target's address can't be resolved to a
    real, existing directory."""


def resolve_path_target_address(raw_path: str) -> str:
    """Resolve RAW_PATH (as given to `target add --kind path`) to an
    absolute, symlink-resolved directory path, and return it as the string
    to store as Target.address.

    Storing the fully-resolved path at registration time -- rather than the
    raw string the operator typed -- means a plugin re-resolving
    target.address at scan time (see plugins/_source_path.py) can detect a
    symlink swap after registration by simple string comparison, without
    needing to remember or re-derive the original input. Shared by the CLI
    and the web API's equivalent endpoint (mirrors
    core/lab.py::resolve_lab_target_address())."""
    path = Path(raw_path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise TargetPathError(f"path '{raw_path}' does not exist: {exc}") from exc
    if not resolved.is_dir():
        raise TargetPathError(f"path '{raw_path}' is not a directory")
    return str(resolved)


class TargetEnvironment(str, Enum):
    """How exposed/authoritative a target is. `PRODUCTION` targets require
    `notes` documenting the authorization/engagement reference (enforced by
    ScopePolicy.add_target(), not just a UI convention)."""

    LOCAL_LAB = "local-lab"
    STAGING = "staging"
    PRODUCTION = "production"


class Target(BaseModel):
    name: str
    kind: TargetKind
    address: str
    allowed_plugins: list[str] = Field(default_factory=list)
    notes: str | None = None
    type: TargetType | None = None
    environment: TargetEnvironment = TargetEnvironment.LOCAL_LAB
    # A registered target that's temporarily off-limits (e.g. a maintenance
    # window, a stakeholder asked to pause). Distinct from allowed_plugins
    # (which plugin names are authorized) -- this blocks every plugin,
    # including "manual"/pivot recording, until `target include` clears it.
    # See ScopePolicy.authorize() and docs/handbook.md §12.
    excluded: bool = False
    exclusion_reason: str | None = None
    # How many scans against this target ScanRunner will let run at once,
    # across every process (CLI invocations and the Web UI both go through
    # the same file-lock-based ConcurrencyGuard). None = unlimited (the
    # existing, unrestricted behavior). See core/concurrency.py.
    max_concurrent: int | None = None


class Engagement(BaseModel):
    """A named group of already-registered Targets that are mutually
    authorized to be referenced together, e.g. "target A was used to reach
    target B" (a pivot/lateral-movement step). Membership alone grants no
    execution rights -- each member Target still needs its own
    `allowed_plugins` to be scanned, and PownForge never executes a pivot
    itself. See ScopePolicy.authorize_pivot() and docs/handbook.md §11."""

    name: str
    targets: list[str] = Field(default_factory=list)
    notes: str | None = None
