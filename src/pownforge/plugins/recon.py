from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


class ReconPlugin(Plugin):
    name = "recon"
    version = "0.1.0"
    description = "Passive subdomain discovery via subfinder (public sources only, no traffic to the target)."
    required_tool = "subfinder"
    expected_kind = TargetKind.HOST
    kind_hint = "address must be a bare domain name, e.g. example.com."

    def __init__(self) -> None:
        self._jsonl_path: Path | None = None

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["subfinder", "-version"]

    def parse_version_output(self, stdout: str, stderr: str) -> str | None:
        # subfinder logs its version as an ANSI-colored "[INF] Current
        # Version: vX.Y.Z" line (to stderr), so strip the escape codes and
        # the log-level prefix rather than storing them verbatim.
        for line in (stdout + "\n" + stderr).splitlines():
            clean = _ANSI_ESCAPE.sub("", line).strip()
            if "Current Version" in clean:
                return clean.split("]", 1)[-1].strip()
        return super().parse_version_output(stdout, stderr)

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        fd, raw_path = tempfile.mkstemp(prefix="pownforge-subfinder-", suffix=".jsonl")
        os.close(fd)
        self._jsonl_path = Path(raw_path)

        args = [
            "subfinder",
            "-d",
            target.address,
            "-oJ",
            "-o",
            str(self._jsonl_path),
            "-silent",
        ]
        if sources := options.get("sources"):
            args += ["-s", str(sources)]
        if exclude_sources := options.get("exclude_sources"):
            args += ["-es", str(exclude_sources)]
        return args

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        subdomains: list[dict[str, Any]] = []
        jsonl_path, self._jsonl_path = self._jsonl_path, None
        if jsonl_path is not None and jsonl_path.exists():
            try:
                subdomains = self._parse_jsonl(jsonl_path)
            finally:
                jsonl_path.unlink(missing_ok=True)

        return {
            "target": target.address,
            "tool": "subfinder",
            "subdomains": subdomains,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }

    @staticmethod
    def _parse_jsonl(jsonl_path: Path) -> list[dict[str, Any]]:
        seen: set[str] = set()
        subdomains: list[dict[str, Any]] = []
        for line in jsonl_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = data.get("host")
            if not host or host in seen:
                continue
            seen.add(host)
            subdomains.append({"host": host, "source": data.get("source")})
        return subdomains
