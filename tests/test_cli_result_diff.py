from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pownforge.cli import app
from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.evidence.store import EvidenceStore

runner = CliRunner()


def _evidence() -> Evidence:
    return Evidence(
        command=["trivy", "image"], started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
        returncode=0, stdout_sha256="a", stderr_sha256="b",
    )


def test_diff_reports_missing_run(tmp_path: Path) -> None:
    result = runner.invoke(app, ["result", "diff", "missing-a", "missing-b", "--workdir", str(tmp_path / "state")])
    assert result.exit_code == 1
    assert "error" in result.stdout.lower() or "error" in result.output.lower()


def test_diff_reports_resolved_still_present_and_new(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "state" / "runs")
    before = RunRecord(
        target="nginx-image-scan", plugin="container", evidence=_evidence(), output={},
        findings=[
            Finding(title="[CVE-2022-1664] dpkg", severity="critical", source="tool"),
            Finding(title="[CVE-2021-3712] openssl", severity="high", source="tool"),
        ],
    )
    after = RunRecord(
        target="nginx-image-scan", plugin="container", evidence=_evidence(), output={},
        findings=[
            Finding(title="[CVE-2021-3712] openssl", severity="high", source="tool"),
            Finding(title="[CVE-2026-5773] curl", severity="high", source="tool"),
        ],
    )
    store.save(before)
    store.save(after)

    result = runner.invoke(
        app, ["result", "diff", before.run_id, after.run_id, "--workdir", str(tmp_path / "state")]
    )

    assert result.exit_code == 0
    assert "resolved (1): CVE-2022-1664" in result.stdout
    assert "still present (1): CVE-2021-3712" in result.stdout
    assert "new only (1): CVE-2026-5773" in result.stdout
