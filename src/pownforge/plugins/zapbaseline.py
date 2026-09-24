"""Passive-only web application scanning via OWASP ZAP's `zap-baseline.py`
(https://www.zaproxy.org/docs/docker/baseline-scan/), run through ZAP's own
official Docker image rather than a locally-installed binary.

Why Docker: ZAP's release tarball (zaproxy.org) does not include
zap-baseline.py or its zap-api-python bindings -- those exist only inside
ZAP's own Docker image build. Reimplementing that build (bundling a JRE,
the ZAP jar, the Python API bindings, and ZAP's internal launcher script)
would duplicate what the ZAP team already builds, tests, and publishes;
this plugin uses their image instead, the same way core/lab.py's
LabManager already shells out to `docker` directly (this plugin's
`required_tool` is `docker`, not `zap`).

Passive-only by construction: `zap-baseline.py` is architecturally a
different script from `zap-full-scan.py`/`zap-api-scan.py` and has no
option to enable active scanning at all -- there is no flag this plugin
could pass, accidentally or otherwise, that would turn it into an active
scan (plugin-additions §7.3).

Known limitation: this shells out to `docker run <image>` itself, so it
needs Docker access from wherever PownForge is running. That already holds
for `pownforge lab add` (LabManager has the same dependency) when running
from the host/`.venv`. It does NOT work from inside PownForge's own
`docker compose run` runtime image without also giving that container
Docker-socket access, which this project does not do (same limitation as
`container`/`sbom`/`imagevuln` scanning a public registry image from
inside `--internal` pownforge-lab -- see docs/handbook.md §6).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError, PluginExecution

_ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

# ZAP's riskcode scale (site.alerts[].riskcode in the JSON report): 0..3.
_SEVERITY_BY_RISKCODE = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}


class ZapBaselinePlugin(Plugin):
    name = "zapbaseline"
    version = "0.1.0"
    description = (
        "Passive-only web application scanning via OWASP ZAP's zap-baseline.py, run through "
        "ZAP's official Docker image. Never runs ZAP's active/full scan."
    )
    required_tool = "docker"
    expected_kind = TargetKind.URL

    options_schema = (
        PluginOption(
            name="network",
            description=(
                "Docker network to attach the ephemeral ZAP container to (so it can reach a "
                "pownforge-lab target by container name). Empty for the default Docker bridge "
                "network (needed to reach a public URL instead)."
            ),
            default="pownforge-lab",
        ),
        PluginOption(
            name="spider_minutes",
            description="zap-baseline.py -m: minutes to spider before the passive scan.",
            default="1",
        ),
    )

    def check(self) -> bool:
        return shutil.which(self.required_tool) is not None

    def version_command(self) -> list[str] | None:
        return ["docker", "--version"]

    def build_command(self, target: Target, options: dict[str, Any], execution: PluginExecution) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)
        try:
            spider_minutes = int(options.get("spider_minutes", "1"))
        except ValueError as exc:
            raise PluginError("zapbaseline plugin --option spider_minutes must be an integer") from exc

        # ZAP's official image runs as its own baked-in "zap" user, whose
        # uid essentially never matches whoever ran `pownforge` -- and
        # zap-baseline.py needs to write into the mounted volume (its
        # report, and an intermediate zap.yaml automation-framework plan).
        # PluginExecution's temp directory is otherwise 0700 (owner-only),
        # which a different-uid container can't write into (confirmed
        # empirically: forcing the container to run as the host uid instead
        # fails a *different* way, since it then can't write ZAP's own
        # $HOME config). Relaxing to world-writable is scoped to this one
        # short-lived per-run temp directory, deleted by ScanRunner right
        # after this run finishes either way.
        os.chmod(execution.workdir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

        args = ["docker", "run", "--rm", "-v", f"{execution.workdir}:/zap/wrk/:rw"]
        network = str(options.get("network", "pownforge-lab")).strip()
        if network:
            args += ["--network", network]
        args += [
            _ZAP_IMAGE,
            "zap-baseline.py",
            "-t",
            target.address,
            "-J",
            "report.json",
            "-m",
            str(spider_minutes),
            # Never fail this process's own exit code on WARN/FAIL -- like
            # every other plugin, ScanRunner records the tool's exit code as
            # Evidence, it doesn't treat "findings exist" as a run failure.
            "-I",
        ]
        return args

    def normalize(
        self, target: Target, raw_stdout: str, raw_stderr: str, execution: PluginExecution
    ) -> dict[str, Any]:
        report_path = execution.path("report.json")
        alerts: list[dict[str, Any]] = []
        if report_path.exists():
            alerts = self._parse_report(report_path)

        return {
            "target": target.address,
            "tool": "zap-baseline",
            "alerts": alerts,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": [
                {
                    "title": alert["name"],
                    "severity": _SEVERITY_BY_RISKCODE.get(alert["riskcode"], "info"),
                    "detail": f"{alert['instance_count']} instance(s), e.g. {alert['example_uri']}",
                }
                for alert in alerts
            ],
        }

    @staticmethod
    def _parse_report(report_path) -> list[dict[str, Any]]:
        try:
            data = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return []
        sites = data.get("site")
        if not isinstance(sites, list):
            return []

        alerts: list[dict[str, Any]] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            for raw in site.get("alerts", []) or []:
                if not isinstance(raw, dict):
                    continue
                instances = raw.get("instances") or []
                example_uri = instances[0].get("uri", "") if instances else ""
                alerts.append(
                    {
                        "plugin_id": raw.get("pluginid", ""),
                        "name": raw.get("name", raw.get("alert", "")),
                        "riskcode": str(raw.get("riskcode", "0")),
                        "confidence": raw.get("confidence", ""),
                        "instance_count": len(instances),
                        "example_uri": example_uri,
                    }
                )
        return alerts
