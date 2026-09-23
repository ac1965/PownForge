from __future__ import annotations

import importlib.resources
import os
import re
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pownforge.core.models import PluginOption, Target, TargetKind
from pownforge.plugins.base import Plugin, PluginError

JOB_NAME = "kube-bench"
JOB_NAMESPACE = "default"
# Matches the compose.yaml project's default image tag (see
# docs/handbook.md §7 "KubeForge(kindクラスタ)への接続"); override via
# --option image=... when the compose project directory has a different name.
DEFAULT_IMAGE = "pownforge-pownforge:latest"

_SUMMARY_RE = re.compile(
    r"== Summary total ==\s*"
    r"(\d+) checks PASS\s*"
    r"(\d+) checks FAIL\s*"
    r"(\d+) checks WARN\s*"
    r"(\d+) checks INFO"
)
_FAIL_RE = re.compile(r"^\[FAIL\]\s+(\S+)\s+(.*)$", re.MULTILINE)


class KubeBenchPlugin(Plugin):
    name = "kube-bench"
    version = "0.1.0"
    description = (
        "CIS Kubernetes Benchmark via kube-bench, run as a Job on the cluster's "
        "control-plane node. Used to measure the effect of hardening changes: "
        "adjust kind-config.yaml's kubeadmConfigPatches, recreate the cluster, "
        "run this again, and compare the PASS/FAIL/WARN counts across the two runs."
    )
    required_tool = "kubectl"
    expected_kind = TargetKind.HOST
    kind_hint = "address should be a kubeconfig context name, e.g. kind-kubeforge-lab."

    options_schema = (
        PluginOption(name="image", description="Image the in-cluster kube-bench Job runs.", default=DEFAULT_IMAGE),
        PluginOption(name="timeout", description="kubectl wait --timeout for the Job.", default="120s"),
    )

    def __init__(self) -> None:
        self._manifest_path: Path | None = None

    def check(self) -> bool:
        return shutil.which("kubectl") is not None

    def build_command(self, target: Target, options: dict[str, Any]) -> list[str]:
        if not self.check():
            raise PluginError(f"'{self.required_tool}' is not installed or not on PATH")
        self.require_kind(target)

        image = str(options.get("image", DEFAULT_IMAGE))
        template = (
            importlib.resources.files("pownforge.plugins").joinpath("_kube_bench_job.yaml").read_text()
        )
        manifest = template.replace("__KUBE_BENCH_IMAGE__", image)

        fd, raw_path = tempfile.mkstemp(prefix="pownforge-kube-bench-", suffix=".yaml")
        os.close(fd)
        self._manifest_path = Path(raw_path)
        self._manifest_path.write_text(manifest)

        ctx = shlex.quote(target.address)
        manifest_arg = shlex.quote(str(self._manifest_path))
        timeout = shlex.quote(str(options.get("timeout", "120s")))
        # 前回runのJobが残っていれば消してから作り直す (再実行可能にするため)。
        # waitの失敗はJobが完了できなかったこと自体を示すが、それでも部分的な
        # ログが取れることがあるので `|| true` で後続のlogsまでは必ず進む。
        script = (
            f"kubectl --context {ctx} delete job {JOB_NAME} -n {JOB_NAMESPACE} "
            f"--ignore-not-found=true >/dev/null 2>&1; "
            f"kubectl --context {ctx} apply -f {manifest_arg} >/dev/null && "
            f"kubectl --context {ctx} wait --for=condition=complete "
            f"job/{JOB_NAME} -n {JOB_NAMESPACE} --timeout={timeout} >/dev/null 2>&1 || true; "
            f"kubectl --context {ctx} logs job/{JOB_NAME} -n {JOB_NAMESPACE}"
        )
        return ["sh", "-c", script]

    def normalize(self, target: Target, raw_stdout: str, raw_stderr: str) -> dict[str, Any]:
        manifest_path, self._manifest_path = self._manifest_path, None
        if manifest_path is not None:
            manifest_path.unlink(missing_ok=True)

        counts = {"pass": 0, "fail": 0, "warn": 0, "info": 0}
        m = _SUMMARY_RE.search(raw_stdout)
        if m:
            counts["pass"], counts["fail"], counts["warn"], counts["info"] = (int(x) for x in m.groups())

        fail_matches = _FAIL_RE.findall(raw_stdout)
        fails = [{"id": fid, "desc": desc} for fid, desc in fail_matches]
        findings = [
            {
                "title": f"[kube-bench {fid}] {desc}",
                "severity": "medium",
                "detail": f"CIS Kubernetes Benchmark check {fid} failed: {desc}",
            }
            for fid, desc in fail_matches
        ]

        return {
            "target": target.address,
            "tool": "kube-bench",
            **counts,
            "fails": fails,
            "raw_stdout": raw_stdout,
            "raw_stderr": raw_stderr,
            "_findings": findings,
        }
