from __future__ import annotations

from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.kube_bench import DEFAULT_IMAGE, KubeBenchPlugin

# Trimmed from a real kube-bench run's output shape (id/desc format, summary
# block) -- see docs/handbook.md's kube-bench section for the full captured
# log this was derived from.
KUBE_BENCH_LOG = """\
[INFO] 1 Control Plane Security Configuration
[FAIL] 1.2.5 Ensure that the --kubelet-certificate-authority argument is set as appropriate (Automated)
[PASS] 1.2.6 Ensure that the --authorization-mode argument is not set to AlwaysAllow (Automated)
[WARN] 1.1.9 Ensure that the Container Network Interface file permissions are set to 600 or more restrictive (Manual)

== Summary total ==
45 checks PASS
4 checks FAIL
12 checks WARN
3 checks INFO
"""


def test_build_command_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubeBenchPlugin()
    monkeypatch.setattr(KubeBenchPlugin, "check", lambda self: True)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")
    execution = PluginExecution(tmp_path)

    command = plugin.build_command(target, {}, execution)

    assert command[0] == "sh" and command[1] == "-c"
    script = command[2]
    assert "kubectl --context kind-kubeforge-lab delete job kube-bench" in script
    assert "kubectl --context kind-kubeforge-lab apply -f" in script
    assert "kubectl --context kind-kubeforge-lab wait --for=condition=complete" in script
    assert "kubectl --context kind-kubeforge-lab logs job/kube-bench" in script

    manifest_path = execution.path("kube-bench-job.yaml")
    manifest = manifest_path.read_text()
    assert DEFAULT_IMAGE in manifest
    assert "__KUBE_BENCH_IMAGE__" not in manifest


def test_build_command_honors_image_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubeBenchPlugin()
    monkeypatch.setattr(KubeBenchPlugin, "check", lambda self: True)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")
    execution = PluginExecution(tmp_path)

    plugin.build_command(target, {"image": "my-registry/pownforge:dev"}, execution)

    manifest = execution.path("kube-bench-job.yaml").read_text()
    assert "my-registry/pownforge:dev" in manifest


def test_build_command_raises_when_tool_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubeBenchPlugin()
    monkeypatch.setattr(KubeBenchPlugin, "check", lambda self: False)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")
    with pytest.raises(PluginError):
        plugin.build_command(target, {}, PluginExecution(tmp_path))


def test_normalize_parses_summary_and_fail_list(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubeBenchPlugin()
    monkeypatch.setattr(KubeBenchPlugin, "check", lambda self: True)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")
    execution = PluginExecution(tmp_path)
    plugin.build_command(target, {}, execution)

    output = plugin.normalize(target, KUBE_BENCH_LOG, "", execution)

    assert output["pass"] == 45
    assert output["fail"] == 4
    assert output["warn"] == 12
    assert output["info"] == 3
    assert output["fails"] == [
        {
            "id": "1.2.5",
            "desc": "Ensure that the --kubelet-certificate-authority argument is set as appropriate (Automated)",
        }
    ]
    assert len(output["_findings"]) == 1
    assert "1.2.5" in output["_findings"][0]["title"]
    assert output["_findings"][0]["severity"] == "medium"


def test_normalize_handles_missing_summary_gracefully(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = KubeBenchPlugin()
    monkeypatch.setattr(KubeBenchPlugin, "check", lambda self: True)
    target = Target(name="kind-lab", kind=TargetKind.HOST, address="kind-kubeforge-lab")
    execution = PluginExecution(tmp_path)
    plugin.build_command(target, {}, execution)

    output = plugin.normalize(target, "", "job failed to schedule", execution)

    assert output["pass"] == 0 and output["fail"] == 0
    assert output["fails"] == []
    assert output["_findings"] == []


def test_version_command_is_none() -> None:
    # kube-bench runs inside the cluster's Job container, not on the machine
    # invoking pownforge, so a local version query wouldn't reflect what ran.
    assert KubeBenchPlugin().version_command() is None
