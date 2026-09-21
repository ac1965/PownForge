from __future__ import annotations

import shutil
from typing import Any

from pownforge.core.models import Target
from pownforge.plugins.base import Plugin, PluginError


class WebPlugin(Plugin):
    name = "web"
    version = "0.1.0"
    description = "Content and endpoint discovery via ffuf."

    def check(self) -> bool:
        return shutil.which("ffuf") is not None

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError("ffuf is not installed or not on PATH")
        wordlist = options.get("wordlist")
        if not wordlist:
            raise PluginError("web plugin requires --option wordlist=<path>")
        url = target.address.rstrip("/") + "/FUZZ"
        return ["ffuf", "-w", str(wordlist), "-u", url, "-of", "json", "-s"]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        return {
            "target": target.address,
            "tool": "ffuf",
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }
