from __future__ import annotations

import shutil
from typing import Any

from pownforge.core.models import Target
from pownforge.plugins.base import Plugin, PluginError


class NetworkPlugin(Plugin):
    name = "network"
    version = "0.1.0"
    description = "TCP/service discovery via nmap."

    def check(self) -> bool:
        return shutil.which("nmap") is not None

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError("nmap is not installed or not on PATH")
        args = ["nmap", "-sV", "-Pn"]
        ports = options.get("ports")
        if ports:
            args += ["-p", str(ports)]
        args.append(target.address)
        return args

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {
            "target": target.address,
            "tool": "nmap",
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }
