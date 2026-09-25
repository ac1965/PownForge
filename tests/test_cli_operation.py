from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pownforge.cli import app

runner = CliRunner()


def test_operation_list_empty_by_default(tmp_path: Path) -> None:
    result = runner.invoke(app, ["operation", "list", "--workdir", str(tmp_path / "state")])
    assert result.exit_code == 0
    assert "no attack operations recorded yet" in result.stdout


def test_operation_list_shows_created_operations(tmp_path: Path) -> None:
    workdir = str(tmp_path / "state")
    result = runner.invoke(
        app, ["operation", "create", "op-1", "--objective", "recon test", "--workdir", workdir]
    )
    assert result.exit_code == 0

    result = runner.invoke(app, ["operation", "list", "--workdir", workdir])
    assert result.exit_code == 0
    assert "op-1\t0 nodes\t0 actions\trecon test" in result.stdout


def test_operation_add_node_edge_action_accept_attack_technique_option(tmp_path: Path) -> None:
    config = str(tmp_path / "targets.yaml")
    workdir = str(tmp_path / "state")
    assert runner.invoke(
        app, ["target", "add", "lab-a", "--address", "127.0.0.1", "--kind", "host", "--config", config]
    ).exit_code == 0
    assert runner.invoke(
        app, ["target", "add", "lab-b", "--address", "127.0.0.2", "--kind", "host", "--config", config]
    ).exit_code == 0
    assert runner.invoke(app, ["operation", "create", "op-1", "--workdir", workdir]).exit_code == 0

    assert runner.invoke(
        app,
        ["operation", "add-node", "op-1", "n-a", "--target", "lab-a", "--attack-technique", "T1595",
         "--workdir", workdir, "--config", config],
    ).exit_code == 0
    assert runner.invoke(
        app,
        ["operation", "add-node", "op-1", "n-b", "--target", "lab-b", "--workdir", workdir, "--config", config],
    ).exit_code == 0
    assert runner.invoke(
        app,
        ["operation", "add-edge", "op-1", "--source", "lab-a", "--destination", "lab-b",
         "--attack-technique", "T1210", "--workdir", workdir, "--config", config],
    ).exit_code == 0
    assert runner.invoke(
        app,
        ["operation", "add-action", "op-1", "a1", "network scan", "--target", "lab-a", "--phase", "discovery",
         "--plugin", "network", "--attack-technique", "T1190,T1210", "--workdir", workdir, "--config", config],
    ).exit_code == 0

    result = runner.invoke(app, ["operation", "show", "op-1", "--workdir", workdir])
    assert result.exit_code == 0
    assert "T1595" in result.stdout
    assert "T1210" in result.stdout
    assert "T1190,T1210" in result.stdout


def test_operation_report_writes_markdown_by_default(tmp_path: Path) -> None:
    workdir = str(tmp_path / "state")
    assert runner.invoke(app, ["operation", "create", "op-1", "--objective", "lab", "--workdir", workdir]).exit_code == 0

    result = runner.invoke(app, ["operation", "report", "op-1", "--workdir", workdir])
    assert result.exit_code == 0

    report_path = tmp_path / "state" / "reports" / "operation-op-1.md"
    assert report_path.exists()
    content = report_path.read_text()
    assert "# Attack Operation: op-1" in content
    assert "Actionがまだありません" in content


def test_operation_report_supports_html_format(tmp_path: Path) -> None:
    workdir = str(tmp_path / "state")
    assert runner.invoke(app, ["operation", "create", "op-1", "--workdir", workdir]).exit_code == 0

    result = runner.invoke(app, ["operation", "report", "op-1", "--format", "html", "--workdir", workdir])
    assert result.exit_code == 0

    report_path = tmp_path / "state" / "reports" / "operation-op-1.html"
    assert report_path.exists()
    assert report_path.read_text().startswith("<!doctype html>")


def test_operation_report_unknown_operation_errors(tmp_path: Path) -> None:
    result = runner.invoke(app, ["operation", "report", "nope", "--workdir", str(tmp_path / "state")])
    assert result.exit_code == 1
