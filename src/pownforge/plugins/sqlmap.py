from __future__ import annotations

import csv
import re
import shutil
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

# sqlmap flags that escalate beyond SQL injection detection/extraction into
# OS/registry/file access, an interactive shell, or a mechanism that could
# smuggle in arbitrary extra sqlmap arguments (bypassing this deny-list
# entirely). risk/level are deliberately NOT capped here: those only control
# how aggressive the *injection-detection* payloads are, which is the actual
# point of running sqlmap at all. This list is the one thing that stays
# fixed regardless of how permissive risk/level are configured, because
# there's no dial for "how much OS access" — it's a different capability
# class than SQLi detection, and one pownforge's scope model can't bound
# once granted (see AGENTS.md: "スコープはコードで強制する").
_DENIED_OPTIONS = frozenset(
    {
        "os-shell",
        "os-pwn",
        "os-smbrelay",
        "os-bof",
        "priv-esc",
        "os-cmd",
        "reg-read",
        "reg-add",
        "reg-del",
        "reg-key",
        "reg-value",
        "reg-data",
        "reg-type",
        "file-read",
        "file-write",
        "file-dest",
        "sql-shell",
        "shell",
        "wizard",
        "eval",
        "tamper",
        "answers",
        "c",
        "configfile",
    }
)

# Matches a block like:
#   Parameter: id (GET)
#       Type: boolean-based blind
#       Title: AND boolean-based blind - WHERE or HAVING clause
#       Payload: id=1 AND 8652=8652
#
#       Type: error-based
#       ...
# up to the next "Parameter:" line, a "---" separator, or end of string.
# Verified against real sqlmap 1.10.9 output (see docs/handbook.md §6).
_PARAMETER_BLOCK_RE = re.compile(
    r"^Parameter:\s*(?P<param>.+?)\s*\((?P<method>[A-Za-z]+)\)\s*$\n"
    r"(?P<body>(?:(?!^Parameter:|^---).*\n?)*)",
    re.MULTILINE,
)
_TECHNIQUE_RE = re.compile(
    r"Type:\s*(?P<type>.+?)\s*\n\s*Title:\s*(?P<title>.+?)\s*\n\s*Payload:\s*(?P<payload>.+?)\s*$",
    re.MULTILINE,
)
_DBMS_RE = re.compile(r"^back-end DBMS:\s*(.+)$", re.MULTILINE)


class SqlmapPlugin(Plugin):
    name = "sqlmap"
    version = "0.1.0"
    description = "SQL injection detection and extraction via sqlmap."
    required_tool = "sqlmap"
    expected_kind = TargetKind.URL
    kind_hint = "The address should include an injectable parameter, e.g. http://host/product?id=1."

    accepts_extra_options = True
    options_schema = (
        PluginOption(name="risk", description="sqlmap --risk (1-3).", default="1", choices=["1", "2", "3"]),
        PluginOption(name="level", description="sqlmap --level (1-5).", default="1", choices=["1", "2", "3", "4", "5"]),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["sqlmap", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        for key in options:
            normalized = key.lstrip("-").lower()
            if normalized in _DENIED_OPTIONS:
                raise PluginError(
                    f"sqlmap option '--{normalized}' is not allowed by pownforge: it "
                    "escalates beyond SQL injection testing (OS/registry/file access, "
                    "an interactive shell, or extra config injection). This is enforced "
                    "regardless of --risk/--level (see docs/handbook.md #6)"
                )

        output_dir = execution.path("output")
        output_dir.mkdir(parents=True, exist_ok=True)

        args = [
            "sqlmap",
            "--url",
            target.address,
            "--batch",
            "--output-dir",
            str(output_dir),
        ]
        args += ["--risk", str(options.get("risk", "1"))]
        args += ["--level", str(options.get("level", "1"))]
        for key, value in options.items():
            normalized = key.lstrip("-").lower()
            if normalized in ("risk", "level"):
                continue
            flag = f"--{normalized}"
            if value in ("", "true", "True"):
                args.append(flag)
            else:
                args += [flag, str(value)]
        return args

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        output_dir = execution.path("output")
        injection_points = self._parse_injection_points(raw_stdout)
        dbms_match = _DBMS_RE.search(raw_stdout)
        dumped_tables: dict[str, list[dict[str, str]]] = {}
        if output_dir.exists():
            dumped_tables = self._collect_dumps(output_dir)

        return {
            "target": target.address,
            "tool": "sqlmap",
            "dbms": dbms_match.group(1) if dbms_match else None,
            "injection_points": injection_points,
            "dumped_tables": dumped_tables,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            # Every confirmed injection technique for a parameter is a
            # genuine tool-confirmed SQL injection, not a guess -- rated
            # critical like other scanners typically treat confirmed SQLi.
            "_findings": [
                {
                    "title": f"SQL injection: {p['parameter']} ({p['method']}) - {t['title']}",
                    "severity": "critical",
                    "detail": f"type={t['type']}; payload={t['payload']}",
                }
                for p in injection_points
                for t in p["techniques"]
            ],
        }

    @staticmethod
    def _parse_injection_points(raw_stdout: str) -> list[dict[str, Any]]:
        points: list[dict[str, Any]] = []
        for match in _PARAMETER_BLOCK_RE.finditer(raw_stdout):
            techniques = [
                {
                    "type": t.group("type").strip(),
                    "title": t.group("title").strip(),
                    "payload": t.group("payload").strip(),
                }
                for t in _TECHNIQUE_RE.finditer(match.group("body"))
            ]
            if not techniques:
                continue
            points.append(
                {
                    "parameter": match.group("param").strip(),
                    "method": match.group("method").strip(),
                    "techniques": techniques,
                }
            )
        return points

    @staticmethod
    def _collect_dumps(output_dir: Path) -> dict[str, list[dict[str, str]]]:
        dumped: dict[str, list[dict[str, str]]] = {}
        for csv_path in output_dir.glob("**/dump/**/*.csv"):
            table = f"{csv_path.parent.name}.{csv_path.stem}"
            with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
                dumped[table] = list(csv.DictReader(fh))
        return dumped
