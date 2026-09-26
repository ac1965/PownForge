from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pownforge.cli import app
from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.evidence.store import EvidenceStore

runner = CliRunner()


def test_correlate_with_no_runs(tmp_path: Path) -> None:
    result = runner.invoke(app, ["result", "correlate", "--target", "lab", "--workdir", str(tmp_path / "state")])
    assert result.exit_code == 0
    assert "no runs recorded for target 'lab'" in result.stdout


def test_correlate_with_no_matching_rules(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "state" / "runs")
    evidence = Evidence(
        command=["nmap", "lab"], started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
        returncode=0, stdout_sha256="a", stderr_sha256="b",
    )
    store.save(RunRecord(target="lab", plugin="network", evidence=evidence, output={"hosts": []}))

    result = runner.invoke(app, ["result", "correlate", "--target", "lab", "--workdir", str(tmp_path / "state")])

    assert result.exit_code == 0
    assert "no correlated risks found" in result.stdout


def test_correlate_reports_matching_risk(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "state" / "runs")
    net_evidence = Evidence(
        command=["nmap", "lab"], started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
        returncode=0, stdout_sha256="a", stderr_sha256="b",
    )
    store.save(
        RunRecord(
            target="lab", plugin="network", evidence=net_evidence,
            output={"hosts": [{"address": "lab", "ports": [{"port": "3306", "state": "open"}]}]},
        )
    )
    trivy_evidence = Evidence(
        command=["trivy", "lab"], started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
        returncode=0, stdout_sha256="a", stderr_sha256="b",
    )
    store.save(
        RunRecord(
            target="lab", plugin="container", evidence=trivy_evidence, output={},
            findings=[Finding(title="CVE-2021-1", severity="critical", source="tool")],
        )
    )

    result = runner.invoke(app, ["result", "correlate", "--target", "lab", "--workdir", str(tmp_path / "state")])

    assert result.exit_code == 0
    assert "high-value-port-with-severe-finding" in result.stdout
    assert "3306" in result.stdout
