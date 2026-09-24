"""Bulk HTTP probing of many paths on ONE registered URL target via
projectdiscovery httpx (https://github.com/projectdiscovery/httpx).

Discovery/fingerprint only: it probes a curated set of paths on the single
authorized target and records each URL's HTTP metadata (status, title,
webserver, detected tech, content length/type, redirect location). It does
not brute-force paths (that's `web`/ffuf) and does not follow redirects or
send payloads.

Scope: every probed URL is built as <registered base>+<absolute path>, and
same-origin is re-checked, so a run can never reach beyond the one registered
target (AGENTS.md: 登録外の対象を叩かない).

Tool-name note: projectdiscovery httpx installs its binary as `httpx`, which
collides with the Python `httpx` library's CLI shim. This plugin needs the
projectdiscovery binary; ensure it is first on PATH (the Docker runtime image
installs it via `go install`).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.api import require_same_origin
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

_RECORDED_FIELDS = (
    "url",
    "status_code",
    "title",
    "webserver",
    "tech",
    "content_length",
    "content_type",
    "location",
)


class HttpxProbePlugin(Plugin):
    name = "httpx"
    version = "0.1.0"
    description = (
        "Bulk HTTP probing of many paths on one registered URL target via projectdiscovery "
        "httpx (status/title/webserver/tech, non-intrusive discovery; not path brute-forcing)."
    )
    required_tool = "httpx"
    expected_kind = TargetKind.URL
    kind_hint = "Register the base URL; paths are probed under it (same-origin)."

    options_schema = (
        PluginOption(
            name="paths",
            description="Comma-separated absolute paths to probe on the target.",
            default="/",
        ),
        PluginOption(
            name="paths_file",
            description="File with one absolute path per line, probed in addition to `paths`.",
        ),
        PluginOption(name="timeout", description="httpx -timeout, seconds.", default="10"),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["httpx", "-version"]

    def _collect_paths(self, options: dict[str, Any]) -> list[str]:
        raw = [p.strip() for p in str(options.get("paths", "/")).split(",")]
        paths_file = options.get("paths_file")
        if paths_file:
            try:
                raw += Path(str(paths_file)).read_text().splitlines()
            except OSError as exc:
                raise PluginError(f"httpx plugin: cannot read paths_file '{paths_file}': {exc}") from exc
        seen: list[str] = []
        for path in (p.strip() for p in raw):
            if not path:
                continue
            if not path.startswith("/") or path.startswith("//"):
                raise PluginError(
                    f"httpx plugin: each path must be an absolute path starting with a single '/', got '{path}'"
                )
            if path not in seen:
                seen.append(path)
        return seen or ["/"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        try:
            timeout = int(options.get("timeout", 10))
        except ValueError as exc:
            raise PluginError("httpx plugin --option timeout must be an integer (seconds)") from exc

        base = target.address.rstrip("/")
        urls: list[str] = []
        for path in self._collect_paths(options):
            url = base + path
            # Defensive: the constructed URL must stay on the registered origin.
            require_same_origin(self.name, target.address, url)
            urls.append(url)

        input_path = execution.path("urls.txt")
        input_path.write_text("\n".join(urls) + "\n")

        # -json: full metadata per line. No -follow-redirects (a redirect is
        # recorded via its location field, never chased off the target).
        return [
            "httpx",
            "-l", str(input_path),
            "-json",
            "-silent",
            "-no-color",
            "-timeout", str(timeout),
        ]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            results.append({field: row.get(field) for field in _RECORDED_FIELDS if field in row})

        return {
            "target": target.address,
            "tool": "httpx",
            "probed": len(results),
            "results": results,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }
