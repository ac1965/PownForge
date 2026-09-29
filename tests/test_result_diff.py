from __future__ import annotations

from pownforge.core.models import Evidence, Finding, RunRecord, Severity
from pownforge.core.result_diff import diff_cves


def _run(target: str, plugin: str, titles: list[str]) -> RunRecord:
    evidence = Evidence(
        command=[plugin, target],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="a",
        stderr_sha256="b",
    )
    findings = [Finding(title=title, severity=Severity.HIGH) for title in titles]
    return RunRecord(target=target, plugin=plugin, evidence=evidence, output={}, findings=findings)


def test_diff_cves_reports_resolved_still_present_and_new() -> None:
    before = _run("nginx-image-scan", "container", ["[CVE-2022-1664] dpkg", "[CVE-2021-3712] openssl"])
    after = _run("nginx-image-scan", "container", ["[CVE-2021-3712] openssl", "[CVE-2026-5773] curl"])

    diff = diff_cves(before, after)

    assert diff.run_a == before.run_id
    assert diff.run_b == after.run_id
    assert diff.resolved == ["CVE-2022-1664"]
    assert diff.still_present == ["CVE-2021-3712"]
    assert diff.new_only == ["CVE-2026-5773"]


def test_diff_cves_ignores_non_cve_bracketed_ids() -> None:
    before = _run("t", "container", ["[AVD-DS-0002] misconfig", "[CVE-2022-1664] dpkg"])
    after = _run("t", "container", ["[AVD-DS-0002] misconfig"])

    diff = diff_cves(before, after)

    assert diff.resolved == ["CVE-2022-1664"]
    assert diff.still_present == []
    assert diff.new_only == []


def test_diff_cves_empty_findings_on_both_sides() -> None:
    before = _run("t", "network", [])
    after = _run("t", "network", [])

    diff = diff_cves(before, after)

    assert diff.resolved == []
    assert diff.still_present == []
    assert diff.new_only == []


def test_diff_cves_deduplicates_repeated_cve_across_findings() -> None:
    before = _run("t", "container", ["[CVE-2018-12886] gcc pkg1", "[CVE-2018-12886] gcc pkg2"])
    after = _run("t", "container", [])

    diff = diff_cves(before, after)

    assert diff.resolved == ["CVE-2018-12886"]
