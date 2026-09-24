from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.secrets import SecretsPlugin

GITLEAKS_REPORT = json.dumps(
    [
        {
            "RuleID": "stripe-access-token",
            "Description": "Found a Stripe Access Token.",
            "StartLine": 4,
            "EndLine": 4,
            "Match": "REDACTED",
            "Secret": "REDACTED",
            "File": "app/config.py",
            "Commit": "",
            "Fingerprint": "app/config.py:stripe-access-token:4",
        },
        # A duplicate fingerprint must be deduped.
        {
            "RuleID": "stripe-access-token",
            "Description": "Found a Stripe Access Token.",
            "StartLine": 4,
            "EndLine": 4,
            "Match": "REDACTED",
            "Secret": "REDACTED",
            "File": "app/config.py",
            "Commit": "",
            "Fingerprint": "app/config.py:stripe-access-token:4",
        },
    ]
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target(tmp_path: Path) -> Target:
    (tmp_path / "repo").mkdir()
    return Target(name="repo", kind=TargetKind.PATH, address=str((tmp_path / "repo").resolve()))


def test_build_command_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SecretsPlugin()
    monkeypatch.setattr(SecretsPlugin, "check", lambda self: True)
    target = _target(tmp_path)
    execution = _execution(tmp_path)

    command = plugin.build_command(target, {}, execution)

    assert command[0] == "gitleaks"
    assert command[1] == "detect"
    assert "--redact" in command
    assert "--no-git" in command  # default: working tree only
    assert "--source" in command and target.address in command
    assert "--exit-code" in command and "0" in command


def test_build_command_history_option_omits_no_git(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SecretsPlugin()
    monkeypatch.setattr(SecretsPlugin, "check", lambda self: True)
    target = _target(tmp_path)

    command = plugin.build_command(target, {"history": "true"}, _execution(tmp_path))

    assert "--no-git" not in command


def test_build_command_rejects_non_path_kind(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SecretsPlugin()
    monkeypatch.setattr(SecretsPlugin, "check", lambda self: True)
    target = Target(name="h", kind=TargetKind.HOST, address="127.0.0.1")
    with pytest.raises(PluginError, match="requires a"):
        plugin.build_command(target, {}, _execution(tmp_path))


def test_build_command_rejects_when_registered_path_no_longer_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = SecretsPlugin()
    monkeypatch.setattr(SecretsPlugin, "check", lambda self: True)
    missing = tmp_path / "gone"
    target = Target(name="gone", kind=TargetKind.PATH, address=str(missing))
    with pytest.raises(PluginError, match="no longer exists"):
        plugin.build_command(target, {}, _execution(tmp_path))


def test_build_command_rejects_a_symlink_swap_since_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The registered target directory was replaced with a symlink pointing
    somewhere else after `target add` -- must be refused, not silently
    followed (refactor-style TOCTOU defense, see plugins/_source_path.py)."""
    plugin = SecretsPlugin()
    monkeypatch.setattr(SecretsPlugin, "check", lambda self: True)
    registered = tmp_path / "repo"
    registered.mkdir()
    registered_address = str(registered.resolve())

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    registered.rmdir()
    registered.symlink_to(elsewhere)

    target = Target(name="repo", kind=TargetKind.PATH, address=registered_address)
    with pytest.raises(PluginError, match="symlink swap"):
        plugin.build_command(target, {}, _execution(tmp_path))


def test_normalize_parses_report_dedupes_and_never_keeps_secret_values(tmp_path: Path) -> None:
    plugin = SecretsPlugin()
    target = _target(tmp_path)
    execution = _execution(tmp_path)
    execution.path("gitleaks.json").write_text(GITLEAKS_REPORT)

    output = plugin.normalize(target, "", "", execution)

    assert len(output["leaks"]) == 1  # deduped by Fingerprint
    leak = output["leaks"][0]
    assert leak["RuleID"] == "stripe-access-token"
    assert leak["Fingerprint"] == "app/config.py:stripe-access-token:4"
    # Neither the finding nor the normalized leak record ever carries the
    # tool's own Secret/Match fields, even redacted ones.
    assert "Secret" not in leak
    assert "Match" not in leak
    dumped = json.dumps(output)
    assert "REDACTED" not in dumped

    findings = output["_findings"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "app/config.py:4" in findings[0]["detail"]


def test_normalize_with_no_report_file_yields_no_leaks(tmp_path: Path) -> None:
    plugin = SecretsPlugin()
    target = _target(tmp_path)
    output = plugin.normalize(target, "", "", _execution(tmp_path))
    assert output["leaks"] == []
    assert output["_findings"] == []


def test_version_command() -> None:
    assert SecretsPlugin().version_command() == ["gitleaks", "version"]


def test_expected_kind_is_path() -> None:
    assert SecretsPlugin().expected_kind == TargetKind.PATH
