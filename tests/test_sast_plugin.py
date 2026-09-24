from __future__ import annotations

import json
from pathlib import Path

import pytest

from pownforge.core.models import Target, TargetKind
from pownforge.plugins.base import PluginError, PluginExecution
from pownforge.plugins.sast import SastPlugin

SEMGREP_REPORT = json.dumps(
    {
        "results": [
            {
                "check_id": "python-sql-string-concat",
                "path": "app/db.py",
                "start": {"line": 12},
                "end": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": "SQL query built via string concatenation.",
                },
            },
            # A duplicate (check_id, path, line) must be deduped.
            {
                "check_id": "python-sql-string-concat",
                "path": "app/db.py",
                "start": {"line": 12},
                "end": {"line": 12},
                "extra": {
                    "severity": "ERROR",
                    "message": "SQL query built via string concatenation.",
                },
            },
            {
                "check_id": "python-eval-exec-use",
                "path": "app/util.py",
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {"severity": "WARNING", "message": "Use of eval()."},
            },
            {
                "check_id": "some-unmapped-severity-rule",
                "path": "app/x.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "SOMETHING_NEW", "message": "unmapped severity."},
            },
        ],
    }
)


def _execution(tmp_path: Path) -> PluginExecution:
    return PluginExecution(tmp_path)


def _target(tmp_path: Path) -> Target:
    (tmp_path / "repo").mkdir()
    return Target(name="repo", kind=TargetKind.PATH, address=str((tmp_path / "repo").resolve()))


def test_build_command_uses_bundled_default_ruleset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SastPlugin()
    monkeypatch.setattr(SastPlugin, "check", lambda self: True)
    target = _target(tmp_path)

    command = plugin.build_command(target, {}, _execution(tmp_path))

    assert command[0] == "semgrep"
    assert command[1] == "scan"
    config_value = command[command.index("--config") + 1]
    assert config_value.endswith("python.yaml")
    assert "--metrics=off" in command
    assert "--no-autofix" in command
    assert "--json" in command


@pytest.mark.parametrize("forbidden", ["auto", "p/security-audit", "r/python", "https://example.com/rules.yaml"])
def test_build_command_rejects_registry_or_url_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, forbidden: str
) -> None:
    plugin = SastPlugin()
    monkeypatch.setattr(SastPlugin, "check", lambda self: True)
    target = _target(tmp_path)
    with pytest.raises(PluginError, match="Registry reference or URL"):
        plugin.build_command(target, {"rules": forbidden}, _execution(tmp_path))


def test_build_command_accepts_a_local_rules_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SastPlugin()
    monkeypatch.setattr(SastPlugin, "check", lambda self: True)
    target = _target(tmp_path)
    custom_rules = tmp_path / "custom.yaml"
    custom_rules.write_text("rules: []")

    command = plugin.build_command(target, {"rules": str(custom_rules)}, _execution(tmp_path))
    assert command[command.index("--config") + 1] == str(custom_rules)


def test_build_command_rejects_unknown_options(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No passthrough of arbitrary semgrep flags (e.g. --autofix): only the
    declared `rules` option is ever accepted (Plugin.validate_options(),
    called by ScanRunner before build_command())."""
    plugin = SastPlugin()
    monkeypatch.setattr(SastPlugin, "check", lambda self: True)
    with pytest.raises(PluginError, match="unknown option"):
        plugin.validate_options({"autofix": "true"})


def test_build_command_rejects_non_path_kind(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    plugin = SastPlugin()
    monkeypatch.setattr(SastPlugin, "check", lambda self: True)
    target = Target(name="h", kind=TargetKind.HOST, address="127.0.0.1")
    with pytest.raises(PluginError, match="requires a"):
        plugin.build_command(target, {}, _execution(tmp_path))


def test_build_command_rejects_a_symlink_swap_since_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plugin = SastPlugin()
    monkeypatch.setattr(SastPlugin, "check", lambda self: True)
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


def test_normalize_parses_report_dedupes_and_maps_severity(tmp_path: Path) -> None:
    plugin = SastPlugin()
    target = _target(tmp_path)
    execution = _execution(tmp_path)
    execution.path("semgrep.json").write_text(SEMGREP_REPORT)

    output = plugin.normalize(target, "", "", execution)

    assert len(output["matches"]) == 3  # deduped the repeated sql-string-concat hit
    findings = output["_findings"]
    assert len(findings) == 3
    by_id = {f["title"]: f for f in findings}
    assert by_id["python-sql-string-concat"]["severity"] == "high"
    assert by_id["python-eval-exec-use"]["severity"] == "medium"
    # An unmapped semgrep severity falls back to "info" rather than being dropped.
    assert by_id["some-unmapped-severity-rule"]["severity"] == "info"


def test_normalize_with_no_report_file_yields_no_matches(tmp_path: Path) -> None:
    plugin = SastPlugin()
    target = _target(tmp_path)
    output = plugin.normalize(target, "", "", _execution(tmp_path))
    assert output["matches"] == []
    assert output["_findings"] == []


def test_version_command() -> None:
    assert SastPlugin().version_command() == ["semgrep", "--version"]


def test_expected_kind_is_path() -> None:
    assert SastPlugin().expected_kind == TargetKind.PATH
