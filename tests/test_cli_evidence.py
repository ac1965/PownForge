from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pownforge.cli import app
from pownforge.evidence.store import EvidenceStore

runner = CliRunner()


def _register_target(config: Path, name: str = "lab") -> None:
    result = runner.invoke(
        app, ["target", "add", name, "--address", "127.0.0.1", "--kind", "host", "--config", str(config)]
    )
    assert result.exit_code == 0, result.stdout


def _import_run(config: Path, workdir: Path) -> str:
    result = runner.invoke(
        app,
        [
            "result", "import", "--target", "lab", "--command", "whoami", "--output", "www-data",
            "--config", str(config), "--workdir", str(workdir),
        ],
    )
    assert result.exit_code == 0, result.stdout
    return EvidenceStore(workdir / "runs").list()[0].run_id


def test_evidence_verify_chain_with_no_runs(tmp_path: Path) -> None:
    result = runner.invoke(app, ["evidence", "verify-chain", "--workdir", str(tmp_path / "state")])
    assert result.exit_code == 0, result.stdout
    assert "no chain entries recorded yet" in result.stdout


def test_evidence_verify_chain_ok_after_imports(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    _register_target(config)
    _import_run(config, workdir)
    _import_run(config, workdir)

    result = runner.invoke(app, ["evidence", "verify-chain", "--workdir", str(workdir)])

    assert result.exit_code == 0, result.stdout
    assert "chain entries checked: 2" in result.stdout
    assert "chain verified" in result.stdout


def test_evidence_verify_chain_detects_tampering(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    _register_target(config)
    run_id = _import_run(config, workdir)

    run_path = workdir / "runs" / f"{run_id}.json"
    data = json.loads(run_path.read_text())
    data["target"] = "tampered"
    run_path.write_text(json.dumps(data))

    result = runner.invoke(app, ["evidence", "verify-chain", "--workdir", str(workdir)])

    assert result.exit_code == 1
    assert "content_mismatch" in result.stderr
    assert "mismatch(es) found" in result.stderr
