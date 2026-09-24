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
