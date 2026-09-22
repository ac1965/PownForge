from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError


class WebPlugin(Plugin):
    name = "web"
    version = "0.1.0"
    description = "Content and endpoint discovery via ffuf."
    required_tool = "ffuf"
    expected_kind = TargetKind.URL

    def __init__(self) -> None:
        self._json_path: Path | None = None

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["ffuf", "-V"]

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        wordlist = options.get("wordlist")
        if not wordlist:
            raise PluginError("web plugin requires --option wordlist=<path>")

        fd, raw_path = tempfile.mkstemp(prefix="pownforge-ffuf-", suffix=".json")
        os.close(fd)
        self._json_path = Path(raw_path)

        url = target.address.rstrip("/") + "/FUZZ"
        return [
            "ffuf",
            "-w",
            str(wordlist),
            "-u",
            url,
            "-o",
            str(self._json_path),
            "-of",
            "json",
            "-s",
            # Auto-calibrate size/word/line filters against randomized paths so
            # an SPA that answers every unknown path with the same catch-all
            # page (e.g. Juice Shop) doesn't drown real hits in false positives.
            "-ac",
        ]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        hits: list[dict[str, Any]] = []
        json_path, self._json_path = self._json_path, None
        if json_path is not None and json_path.exists():
            try:
                hits = self._parse_json(json_path)
            finally:
                json_path.unlink(missing_ok=True)

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
