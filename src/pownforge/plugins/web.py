from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution


class WebPlugin(Plugin):
    name = "web"
    version = "0.1.0"
    description = "Content and endpoint discovery via ffuf."
    required_tool = "ffuf"
    expected_kind = TargetKind.URL

    options_schema = (
        PluginOption(name="wordlist", description="ffuf -w wordlist path.", required=True),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["ffuf", "-V"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        wordlist = options.get("wordlist")
        if not wordlist:
            raise PluginError("web plugin requires --option wordlist=<path>")

        json_path = execution.path("ffuf.json")
        url = target.address.rstrip("/") + "/FUZZ"
        return [
            "ffuf",
            "-w",
            str(wordlist),
            "-u",
            url,
            "-o",
            str(json_path),
            "-of",
            "json",
            "-s",
            # Auto-calibrate size/word/line filters against randomized paths so
            # an SPA that answers every unknown path with the same catch-all
            # page (e.g. Juice Shop) doesn't drown real hits in false positives.
            "-ac",
        ]

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        hits: list[dict[str, Any]] = []
        json_path = execution.path("ffuf.json")
        if json_path.exists():
            hits = self._parse_json(json_path)

        return {
            "target": target.address,
            "tool": "ffuf",
            "hits": hits,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
        }

    @staticmethod
    def _parse_json(json_path: Path) -> list[dict[str, Any]]:
        try:
            data = json.loads(json_path.read_text())
        except (json.JSONDecodeError, OSError):
            return []

        hits: list[dict[str, Any]] = []
        for result in data.get("results", []):
            hits.append(
                {
                    "path": result.get("input", {}).get("FUZZ"),
                    "url": result.get("url"),
                    "status": result.get("status"),
                    "length": result.get("length"),
                    "words": result.get("words"),
                }
            )
        return hits
