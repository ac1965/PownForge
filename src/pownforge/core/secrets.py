from __future__ import annotations

_REDACTED = "***"

# Not a fixed per-tool flag list (nmap/ffuf/nuclei/trivy/sqlmap today don't
# take credentials at all) but a keyword heuristic, since a future plugin
# that does (identity/auth-aware scans, or --header/--cookie on an
# authenticated web/nuclei scan) isn't known yet. Matched as a substring of
# the flag name, case-insensitively, so "--api-key", "apikey", "Api-Key",
# "--auth-cred" etc. all match.
_SENSITIVE_KEYWORDS = (
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "cookie",
    "header",
    "apikey",
    "api-key",
    "credential",
    "cred",
)


def _flag_name(token: str) -> str | None:
    """Return TOKEN's flag name (lowercase, leading dashes and any "=value"
    stripped) if it looks like a flag ("-x", "--xxx", "--xxx=yyy"), else
    None."""
    if not token.startswith("-"):
        return None
    name = token.lstrip("-")
    if "=" in name:
        name = name.split("=", 1)[0]
    return name.lower()


def _is_sensitive(flag_name: str) -> bool:
    return any(keyword in flag_name for keyword in _SENSITIVE_KEYWORDS)


def mask_command(command: list[str]) -> list[str]:
    """Return a copy of COMMAND with values following credential-looking
    flags redacted, for storage in Evidence.command (never for the argv
    actually passed to subprocess -- that stays unmasked so the tool keeps
    working). Handles both "--flag value" (two tokens) and "--flag=value"
    (one token). A flag's value is only masked when it's the very next
    token and doesn't itself look like another flag."""
    masked = list(command)
    i = 0
    while i < len(masked):
        name = _flag_name(masked[i])
        if name is not None and _is_sensitive(name):
            if "=" in masked[i]:
                flag_part = masked[i].split("=", 1)[0]
                masked[i] = f"{flag_part}={_REDACTED}"
            elif i + 1 < len(masked) and not masked[i + 1].startswith("-"):
                masked[i + 1] = _REDACTED
                i += 1
        i += 1
    return masked
