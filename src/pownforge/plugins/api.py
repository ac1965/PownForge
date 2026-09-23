from __future__ import annotations

import shutil
from typing import Any
from urllib.parse import urlparse

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError

# State-changing methods (POST/PUT/PATCH/DELETE) are deliberately excluded:
# this plugin observes an API, it never modifies data on the target.
_ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
_DEFAULT_TIMEOUT_SECONDS = 30
_MAX_BODY_CHARS = 20_000

_SECURITY_HEADERS = {
    "x-content-type-options": ("low", "X-Content-Type-Options header missing"),
    "content-security-policy": ("info", "Content-Security-Policy header missing"),
}


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def require_same_origin(plugin_name: str, base: str, url: str) -> None:
    b, u = urlparse(base), urlparse(url)
    same = (
        b.scheme == u.scheme
        and b.hostname == u.hostname
        and (b.port or _default_port(b.scheme)) == (u.port or _default_port(u.scheme))
        and not u.username
    )
    if not same:
        raise PluginError(f"{plugin_name} plugin refused: {url} is not on the registered target {base}")


def parse_http_response(raw: str) -> tuple[int | None, str, dict[str, str], str]:
    text = raw.replace("\r\n", "\n")
    # Skip interim responses (e.g. "HTTP/1.1 100 Continue") curl -i also prints.
    while True:
        head, sep, rest = text.partition("\n\n")
        lines = head.split("\n")
        if not lines[0].startswith("HTTP/"):
            return None, "", {}, raw
        parts = lines[0].split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        if status is not None and 100 <= status < 200 and rest.startswith("HTTP/"):
            text = rest
            continue
        headers: dict[str, str] = {}
        for line in lines[1:]:
            key, colon, value = line.partition(":")
            if colon:
                headers[key.strip().lower()] = value.strip()
        return status, parts[2] if len(parts) > 2 else "", headers, rest if sep else ""


class ApiPlugin(Plugin):
    name = "api"
    version = "0.1.0"
    description = "Single HTTP request to an API endpoint via curl; passive header checks."
    required_tool = "curl"
    expected_kind = TargetKind.URL

    options_schema = (
        PluginOption(name="path", description="Absolute path appended to the target URL.", default="/"),
        PluginOption(name="method", description="HTTP method.", default="GET", choices=sorted(_ALLOWED_METHODS)),
        PluginOption(name="timeout", description="curl --max-time, seconds.", default=str(_DEFAULT_TIMEOUT_SECONDS)),
    )

    def __init__(self) -> None:
        self._request: dict[str, str] | None = None

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["curl", "--version"]

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        method = str(options.get("method", "GET")).upper()
        if method not in _ALLOWED_METHODS:
            raise PluginError(
                f"api plugin only allows {', '.join(sorted(_ALLOWED_METHODS))} (got {method})"
            )
        path = str(options.get("path", "/"))
        # "//host" or "@host" appended to the base URL would change the
        # effective host, so require a plain absolute path and re-check below.
        if not path.startswith("/") or path.startswith("//"):
            raise PluginError("api plugin --option path must start with a single '/'")
        try:
            timeout = int(options.get("timeout", _DEFAULT_TIMEOUT_SECONDS))
        except ValueError as exc:
            raise PluginError("api plugin --option timeout must be an integer (seconds)") from exc

        url = target.address.rstrip("/") + path
        require_same_origin(self.name, target.address, url)
        self._request = {"url": url, "method": method}

        command = [
            "curl", "-sS", "-i",
            "--max-time", str(timeout),
            # No -L: a redirect is recorded as-is, never followed (it could
            # point outside the registered target).
            "--proto", "=http,https",
        ]
        # curl warns that "-X HEAD" can hang waiting for a body; -I is the HEAD form.
        command += ["-I"] if method == "HEAD" else ["-X", method]
        command.append(url)
        return command

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        request, self._request = self._request or {}, None
        status, reason, headers, body = parse_http_response(raw_stdout)
        truncated = len(body) > _MAX_BODY_CHARS
        return {
            "target": target.address,
            "tool": "curl",
            "url": request.get("url", target.address),
            "method": request.get("method", "GET"),
            "status": status,
            "reason": reason,
            "headers": headers,
            "body": body[:_MAX_BODY_CHARS],
            "body_truncated": truncated,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": self._findings(request.get("url", target.address), status, headers),
        }

    @staticmethod
    def _findings(url: str, status: int | None, headers: dict[str, str]) -> list[dict[str, str]]:
        if status is None:
            return []
        findings: list[dict[str, str]] = []
        for header, (severity, title) in _SECURITY_HEADERS.items():
            if header not in headers:
                findings.append({"title": title, "severity": severity, "detail": url})
        if url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(
                {"title": "Strict-Transport-Security header missing", "severity": "low", "detail": url}
            )
        for header in ("server", "x-powered-by"):
            value = headers.get(header, "")
            if any(ch.isdigit() for ch in value):
                findings.append(
                    {
                        "title": f"Version disclosed in {header} header",
                        "severity": "info",
                        "detail": f"{header}: {value}",
                    }
                )
        if headers.get("access-control-allow-origin") == "*":
            findings.append(
                {
                    "title": "CORS allows any origin (Access-Control-Allow-Origin: *)",
                    "severity": "low",
                    "detail": url,
                }
            )
        return findings
