"""Shared identifier validation for names that get interpolated into a
Store's filesystem path (e.g. `f"{name}.json"`, `f"{name}.kubeconfig"`).

Enforced at each Store's *creation* entry point (ScopePolicy.add_target,
create_operation, create_attack_session, LabManager.add, ...) -- never at
CLI argument parsing alone, and never on a lookup/load path. See the
refactor instructions §4.4.

Compatibility with existing data: this module only gates *new* names being
registered. `Store.load()`/`resolve()`/`list()` never call this -- a record
already on disk under a name that predates this policy stays loadable. Only
a plain `str` name is ever turned into a path (Pydantic's `str` typing
already excludes non-string input), so the only thing worth restricting is
the character set the path-join step trusts blindly.
"""

from __future__ import annotations

import re

MAX_LENGTH = 100

# ASCII letters/digits/dot/dash/underscore only, first and last character
# must be alphanumeric. This blocks every case §4.4 asks for by
# construction, not by special-casing them:
#   - a path separator ("/", "\\")   -> not in the character class
#   - ".." (directory traversal)     -> "." can't be the last character
#   - a leading "."                  -> "." can't be the first character
#   - an empty string                -> the pattern requires >=1 character
_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,%d}[A-Za-z0-9])?$" % (MAX_LENGTH - 2))


class IdentifierError(ValueError):
    """Raised when a name is unsafe to use as (part of) a filesystem path."""


def validate_identifier(name: str, *, kind: str = "identifier") -> str:
    """Raise IdentifierError if NAME is unsafe to interpolate into a Store
    path; otherwise return it unchanged (so call sites can do
    `name = validate_identifier(name, kind="target")`)."""
    if not name:
        raise IdentifierError(f"{kind} name must not be empty")
    if len(name) > MAX_LENGTH:
        raise IdentifierError(f"{kind} name must be at most {MAX_LENGTH} characters (got {len(name)})")
    if not _PATTERN.match(name):
        raise IdentifierError(
            f"{kind} name {name!r} is invalid: use only letters, digits, '.', '-', '_', "
            "and start/end with a letter or digit"
        )
    return name
