from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.iac import IacPlugin

CHECKOV_REPORT_SINGLE_FRAMEWORK = json.dumps(
    {
        "check_type": "kubernetes",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_K8S_16",
                    "check_name": "Container should not be privileged",
                    "resource": "Pod.default.bad-pod",
                    "file_path": "/pod.yaml",
                },
                # Duplicate (check_id, resource, file_path) must be deduped.
                {
                    "check_id": "CKV_K8S_16",
                    "check_name": "Container should not be privileged",
                    "resource": "Pod.default.bad-pod",
                    "file_path": "/pod.yaml",
                },
            ],
        },
        "summary": {"passed": 69, "failed": 19, "skipped": 0},
    }
)

CHECKOV_REPORT_MULTI_FRAMEWORK = json.dumps(
    [
        {
            "check_type": "kubernetes",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_16",
                        "check_name": "Container should not be privileged",
                        "resource": "Pod.default.bad-pod",
                        "file_path": "/pod.yaml",
                    }
                ]
            },
            "summary": {"passed": 69, "failed": 1, "skipped": 0},
        },
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 Bucket has an ACL defined which allows public READ access",
                        "resource": "aws_s3_bucket.bad",
                        "file_path": "/main.tf",
                    }
                ]
            },
            "summary": {"passed": 1, "failed": 1, "skipped": 0},
        },
    ]
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target(tmp_path: Path) -> Target:
    (tmp_path / "manifests").mkdir()
    return Target(name="manifests", kind=TargetKind.PATH, address=str((tmp_path / "manifests").resolve()))


def test_build_command_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = IacPlugin()
    monkeypatch.setattr(IacPlugin, "check", lambda self: True)
    target = _target(tmp_path)

    command = plugin.build_command(target, {}, _execution(tmp_path))

    assert command[0] == "checkov"
    assert "--directory" in command and target.address in command
    assert "--framework" in command
    fi = command.index("--framework")
    assert command[fi + 1 : fi + 4] == ["kubernetes", "terraform", "dockerfile"]
    assert "--skip-download" in command
    assert "--skip-results-upload" in command
    assert not any("bc-api-key" in part for part in command)


def test_build_command_honors_framework_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = IacPlugin()
    monkeypatch.setattr(IacPlugin, "check", lambda self: True)
    target = _target(tmp_path)

    command = plugin.build_command(target, {"framework": "terraform"}, _execution(tmp_path))
    fi = command.index("--framework")
    assert command[fi + 1] == "terraform"
    assert command[fi + 2] == "--output"  # only one framework token, nothing else slipped in


def test_build_command_rejects_non_path_kind(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = IacPlugin()
    monkeypatch.setattr(IacPlugin, "check", lambda self: True)
    target = Target(name="h", kind=TargetKind.HOST, address="127.0.0.1")
    with pytest.raises(PluginError, match="requires a"):
        plugin.build_command(target, {}, _execution(tmp_path))


def test_build_command_rejects_a_symlink_swap_since_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = IacPlugin()
    monkeypatch.setattr(IacPlugin, "check", lambda self: True)
    registered = tmp_path / "manifests"
    registered.mkdir()
    registered_address = str(registered.resolve())
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    registered.rmdir()
    registered.symlink_to(elsewhere)

    target = Target(name="manifests", kind=TargetKind.PATH, address=registered_address)
    with pytest.raises(PluginError, match="symlink swap"):
        plugin.build_command(target, {}, _execution(tmp_path))


def test_normalize_parses_single_framework_report_and_dedupes(tmp_path: Path) -> None:
    plugin = IacPlugin()
    target = _target(tmp_path)
    execution = _execution(tmp_path)
    output_dir = execution.path("checkov-output")
    output_dir.mkdir()
    (output_dir / "results_json.json").write_text(CHECKOV_REPORT_SINGLE_FRAMEWORK)

    output = plugin.normalize(target, "", "", execution)

    assert len(output["failures"]) == 1  # deduped
    assert output["summary"] == {"passed": 69, "failed": 19, "skipped": 0}
    findings = output["_findings"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "CKV_K8S_16" in findings[0]["title"]
    assert "Pod.default.bad-pod" in findings[0]["detail"]


def test_normalize_parses_multi_framework_report_and_sums_summary(tmp_path: Path) -> None:
    plugin = IacPlugin()
    target = _target(tmp_path)
    execution = _execution(tmp_path)
    output_dir = execution.path("checkov-output")
    output_dir.mkdir()
    (output_dir / "results_json.json").write_text(CHECKOV_REPORT_MULTI_FRAMEWORK)

    output = plugin.normalize(target, "", "", execution)

    assert len(output["failures"]) == 2
    assert output["summary"] == {"passed": 70, "failed": 2, "skipped": 0}
    titles = {f["title"] for f in output["_findings"]}
    assert any("CKV_K8S_16" in t for t in titles)
    assert any("CKV_AWS_20" in t for t in titles)


def test_normalize_with_no_report_yields_no_failures(tmp_path: Path) -> None:
    plugin = IacPlugin()
    target = _target(tmp_path)
    output = plugin.normalize(target, "", "", _execution(tmp_path))
    assert output["failures"] == []
    assert output["_findings"] == []


def test_version_command() -> None:
    assert IacPlugin().version_command() == ["checkov", "--version"]


def test_expected_kind_is_path() -> None:
    assert IacPlugin().expected_kind == TargetKind.PATH
