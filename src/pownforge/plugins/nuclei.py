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


class NucleiPlugin(Plugin):
    name = "nuclei"
    version = "0.1.0"
    description = "Template-based vulnerability detection via nuclei."
    required_tool = "nuclei"
    expected_kind = TargetKind.URL

    def __init__(self) -> None:
        self._jsonl_path: Path | None = None

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["nuclei", "-version"]

    def parse_version_output(self, stdout: str, stderr: str) -> str | None:
        # nuclei always logs a Go-runtime warning to stderr ahead of the
        # actual version line, so the base class's "first line" heuristic
        # would report the warning instead. Find the real line explicitly.
        for line in (stdout + "\n" + stderr).splitlines():
            clean = _ANSI_ESCAPE.sub("", line).strip()
            if "Nuclei Engine Version" in clean:
                return clean.split("]", 1)[-1].strip()
        return super().parse_version_output(stdout, stderr)

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        fd, raw_path = tempfile.mkstemp(prefix="pownforge-nuclei-", suffix=".jsonl")
        os.close(fd)
        self._jsonl_path = Path(raw_path)

        args = [
            "nuclei",
            "-u",
            target.address,
            "-jsonl",
            "-o",
            str(self._jsonl_path),
            "-silent",
        ]
        if tags := options.get("tags"):
            args += ["-tags", str(tags)]
        if severity := options.get("severity"):
            args += ["-severity", str(severity)]
        if templates := options.get("templates"):
            args += ["-t", str(templates)]
        return args

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        matches: list[dict[str, Any]] = []
        jsonl_path, self._jsonl_path = self._jsonl_path, None
        if jsonl_path is not None and jsonl_path.exists():
            try:
                matches = self._parse_jsonl(jsonl_path)
            finally:
                jsonl_path.unlink(missing_ok=True)

        return {
            "target": target.address,
            "tool": "nuclei",
            "matches": matches,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            # Each nuclei template match already carries its own name/
            # severity/description, so it's a genuine tool-native candidate
            # finding — not just raw text for `pownforge analyze` to guess
            # at. ScanRunner turns these into real Findings (source="tool",
            # status starts at needs-review like everything else).
            "_findings": [
                {
                    "title": match["name"] or match["template_id"] or "nuclei match",
                    "severity": match["severity"],
                    "detail": match["description"] or match["matched_at"] or "",
                }
                for match in matches
            ],
        }

    @staticmethod
    def _parse_jsonl(jsonl_path: Path) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for line in jsonl_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = data.get("info") or {}
            matches.append(
                {
                    "template_id": data.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "description": info.get("description"),
                    "matched_at": data.get("matched-at") or data.get("host"),
                }
            )
        return matches
