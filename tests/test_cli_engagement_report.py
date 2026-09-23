from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from pownforge.cli import app
from pownforge.core.models import (
    Claim,
    ConfidenceLevel,
    Evidence,
    Finding,
    PreconditionReport,
    PrimitiveEvidence,
    PrimitiveRunRecord,
    RunRecord,
    Severity,
    ValidationLevel,
)
from pownforge.evidence.primitive_store import PrimitiveRunStore
from pownforge.evidence.store import EvidenceStore

runner = CliRunner()
_T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _seed(workdir: Path, target: str = "lab") -> None:
    ev = Evidence(command=["nmap", target], started_at=_T0, finished_at=_T0, returncode=0,
                  stdout_sha256="a", stderr_sha256="b")
    EvidenceStore(workdir / "runs").save(
        RunRecord(target=target, plugin="network", evidence=ev,
                  findings=[Finding(title="port", severity=Severity.LOW, source="tool")])
    )
    PrimitiveRunStore(workdir / "primitive_runs").save(
        PrimitiveRunRecord(
            primitive="http.oob-interaction", target=target,
            requested_level=ValidationLevel.VALIDATION, level_reached=ValidationLevel.VALIDATION,
            preconditions=PreconditionReport(),
            evidence=PrimitiveEvidence(
                target=target, primitive="http.oob-interaction",
                claims=[Claim(statement="oob", confidence=ConfidenceLevel.CONFIRMED)],
            ),
        )
    )


def test_engagement_report_target_scope(tmp_path: Path) -> None:
    workdir = tmp_path / "state"
    _seed(workdir)
    result = runner.invoke(app, ["report", "engagement", "--target", "lab", "--workdir", str(workdir)])
    assert result.exit_code == 0, result.stdout
    report = (workdir / "reports" / "engagement-target-lab.md").read_text()
    assert "**scan**" in report and "**primitive**" in report


def test_engagement_report_all_scope_html(tmp_path: Path) -> None:
    workdir = tmp_path / "state"
    _seed(workdir)
    result = runner.invoke(app, ["report", "engagement", "--format", "html", "--workdir", str(workdir)])
    assert result.exit_code == 0, result.stdout
    assert (workdir / "reports" / "engagement-all.html").read_text().startswith("<!doctype html>")


def test_engagement_report_empty_scope_errors(tmp_path: Path) -> None:
    result = runner.invoke(app, ["report", "engagement", "--target", "ghost", "--workdir", str(tmp_path / "s")])
    assert result.exit_code == 1
    assert "no runs" in result.stderr


def test_engagement_report_rejects_both_scopes(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["report", "engagement", "--target", "a", "--engagement", "b", "--workdir", str(tmp_path / "s")]
    )
    assert result.exit_code == 1
    assert "not both" in result.stderr
