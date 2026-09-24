"""Liveness/tech-stack triage across MANY hosts via projectdiscovery httpx
(https://github.com/projectdiscovery/httpx) -- distinct from the `httpx`
plugin (plugins/httpx_probe.py), which probes many PATHS on ONE already-
registered URL target. This plugin answers "of these N candidate hosts
(typically `recon`'s subdomain output), which are alive and what are they
running" -- a triage step for deciding where to point `web`/`nuclei`/`sqlmap`
next, not path/content discovery.

Scope (plugin-additions §7.1): a subdomain `recon` found is not itself
authorized scope -- each candidate must already be its own registered
Target. `hosts` therefore takes Target *names*, not raw hostnames/URLs;
ScanRunner (Plugin.host_list_option, see plugins/base.py) authorizes each
one via the same ScopePolicy.authorize() the primary target already goes
through, before build_command() ever sees them. A name that isn't
registered/allowed is excluded and recorded, never silently dropped and
never contacted.

Tool-name note: same collision as the `httpx` plugin -- this needs the
projectdiscovery binary, not the Python `httpx` library's CLI shim.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# Same fields the `httpx` plugin (plugins/httpx_probe.py) records -- kept as
# its own copy rather than a shared import so the two plugins' output shapes
# can drift independently without one accidentally changing the other.
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

_DEFAULT_RATE_LIMIT = 10
"""httpx's own default is 150 req/s; this plugin's default is deliberately
much lower (§7.1: 通信レートの上限...デフォルトを保守的にする) since a
`hosts` batch can span many independently-registered targets at once,
unlike a single-target scan."""


class HttpProbePlugin(Plugin):
    name = "httpprobe"
    version = "0.1.0"
    description = (
        "Liveness/tech-stack triage across many already-registered hosts via projectdiscovery "
        "httpx (e.g. triaging `recon`'s subdomain output before pointing web/nuclei/sqlmap at one)."
    )
    required_tool = "httpx"
    expected_kind = TargetKind.HOST
    kind_hint = "register an anchor target (e.g. the domain `recon` was run against)."
    host_list_option = "hosts"

    options_schema = (
        PluginOption(
            name="hosts",
            description=(
                "Comma-separated names of already-registered Targets to probe "
                "(not raw hostnames -- each must be registered and allow httpprobe)."
            ),
            required=True,
        ),
        PluginOption(
            name="rate_limit",
            description="httpx -rate-limit, max requests per second across all hosts.",
            default=str(_DEFAULT_RATE_LIMIT),
        ),
        PluginOption(name="timeout", description="httpx -timeout, seconds per request.", default="10"),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["httpx", "-version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        try:
            timeout = int(options.get("timeout", 10))
        except ValueError as exc:
            raise PluginError("httpprobe plugin --option timeout must be an integer (seconds)") from exc
        try:
            rate_limit = int(options.get("rate_limit", _DEFAULT_RATE_LIMIT))
        except ValueError as exc:
            raise PluginError("httpprobe plugin --option rate_limit must be an integer") from exc

        # By the time build_command() runs, ScanRunner has already replaced
        # `hosts` with the comma-separated *addresses* of only the names
        # that passed ScopePolicy.authorize() (see Plugin.host_list_option).
        # An empty result here means every requested name was rejected (or
        # none were given) -- nothing left to probe.
        addresses = [h.strip() for h in str(options.get("hosts", "")).split(",") if h.strip()]
        if not addresses:
            raise PluginError(
                "httpprobe plugin: no authorized hosts to probe (every name in --option hosts "
                "was rejected by scope, or the option was empty) -- see the run's excluded_hosts"
            )

        hosts_path = execution.path("hosts.txt")
        hosts_path.write_text("\n".join(addresses) + "\n")

        # No -follow-redirects, same as the `httpx` plugin: a redirect is
        # recorded via its `location` field, never chased (chasing one could
        # leave every authorized host's own scope).
        return [
            "httpx",
            "-l", str(hosts_path),
            "-json",
            "-silent",
            "-no-color",
            "-timeout", str(timeout),
            "-rate-limit", str(rate_limit),
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

        excluded_hosts = execution.data.get("excluded_hosts", [])

        return {
            "target": target.address,
            "tool": "httpx",
            "probed": len(results),
            "results": results,
            # Names from --option hosts that ScopePolicy rejected -- never
            # contacted, but never silently dropped either (§7.1).
            "excluded_hosts": excluded_hosts,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }
