from __future__ import annotations

import re
import shutil
from typing import Any

from pownforge.sdk import FindingDict, Plugin, PluginError, PluginOption, Target, TargetKind

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class HttpTitlePlugin(Plugin):
    name = "http-title"
    version = "0.1.0"
    description = "GET the target URL once and record the HTML <title> (SDK example)."
    required_tool = "curl"
    expected_kind = TargetKind.URL
    options_schema = (
        PluginOption(name="timeout", description="curl --max-time, seconds.", default="10"),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["curl", "--version"]

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        # Only argv is returned; PownForge's ScanRunner runs it after
        # ScopePolicy has authorized the target.
        self.require_kind(target)
        timeout = str(options.get("timeout", "10"))
        if not timeout.isdigit():
            raise PluginError("http-title plugin --option timeout must be an integer")
        return ["curl", "-sS", "--max-time", timeout, "--proto", "=http,https", target.address]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        match = _TITLE_RE.search(raw_stdout)
        title = " ".join(match.group(1).split()) if match else None
        findings: list[FindingDict] = []
        if title is None and raw_stdout:
            findings.append({"title": "Page has no <title>", "severity": "info", "detail": target.address})
        return {
            "target": target.address,
            "tool": "curl",
            "title": title,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": findings,
        }
