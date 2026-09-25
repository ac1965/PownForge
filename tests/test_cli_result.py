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


def test_result_import_records_a_run(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    _register_target(config)

    result = runner.invoke(
        app,
        [
            "result", "import",
            "--target", "lab",
            "--command", "msfconsole -x 'use exploit/...; run'",
            "--output", "whoami\nwww-data",
            "--tool", "msfconsole",
            "--config", str(config), "--workdir", str(workdir),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "recorded (target=lab, plugin=manual)" in result.stdout

    store = EvidenceStore(workdir / "runs")
    records = store.list()
    assert len(records) == 1
    assert records[0].findings == []


def test_result_import_with_finding_title_attaches_a_finding_in_one_call(tmp_path: Path) -> None:
    """refactor v3 §2: this used to require a separate `result add-finding`
    call after `result import`, copy-pasting the run_id it printed."""
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    _register_target(config)

    result = runner.invoke(
        app,
        [
            "result", "import",
            "--target", "lab",
            "--command", "whoami",
            "--output", "www-data",
            "--finding-title", "Got a shell as www-data",
            "--finding-severity", "critical",
            "--finding-detail", "via CVE-2014-6271",
            "--config", str(config), "--workdir", str(workdir),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "recorded (target=lab, plugin=manual)" in result.stdout
    assert "added to run" in result.stdout
    assert "(status=needs-review)" in result.stdout

    store = EvidenceStore(workdir / "runs")
    record = store.list()[0]
    assert len(record.findings) == 1
    finding = record.findings[0]
    assert finding.title == "Got a shell as www-data"
    assert finding.severity == "critical"
    assert finding.detail == "via CVE-2014-6271"
    assert finding.source == "manual"
    assert finding.status == "needs-review"  # still requires an explicit `result review`


def test_result_import_without_finding_title_does_not_touch_findings(tmp_path: Path) -> None:
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    _register_target(config)

    result = runner.invoke(
        app,
        [
            "result", "import",
            "--target", "lab",
            "--command", "whoami",
            "--output", "www-data",
            "--finding-severity", "critical",  # passed, but no --finding-title
            "--config", str(config), "--workdir", str(workdir),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "added to run" not in result.stdout

    store = EvidenceStore(workdir / "runs")
    assert store.list()[0].findings == []


def test_result_import_and_add_finding_then_review(tmp_path: Path) -> None:
    """The pre-existing multi-command path still works unchanged."""
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    _register_target(config)

    import_result = runner.invoke(
        app,
        [
            "result", "import", "--target", "lab", "--command", "whoami", "--output", "www-data",
            "--config", str(config), "--workdir", str(workdir),
        ],
    )
    run_id = json.loads(
        EvidenceStore(workdir / "runs").list()[0].model_dump_json()
    )["run_id"]
    assert import_result.exit_code == 0

    add_result = runner.invoke(
        app,
        ["result", "add-finding", run_id, "--title", "Shell", "--severity", "high", "--workdir", str(workdir)],
    )
    assert add_result.exit_code == 0, add_result.stdout
    finding_id = EvidenceStore(workdir / "runs").load(run_id).findings[0].finding_id

    review_result = runner.invoke(
        app, ["result", "review", run_id, finding_id, "confirmed", "--workdir", str(workdir)]
    )
    assert review_result.exit_code == 0, review_result.stdout
    assert EvidenceStore(workdir / "runs").load(run_id).findings[0].status == "confirmed"
