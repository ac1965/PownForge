from __future__ import annotations

from pownforge.plugins._trivy import findings_from_trivy_results


# CVSS shape captured from a real `trivy image -f json alpine:3.10` run
# (trivy 0.74.0, CVE-2021-36159) -- see docs/handbook.md §3.5.
_REAL_CVSS = {
    "nvd": {
        "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P",
        "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
        "V2Score": 6.4,
        "V3Score": 9.1,
    },
    "redhat": {
        "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
        "V3Score": 9.1,
    },
}


def test_vulnerability_finding_carries_cvss_and_native_severity() -> None:
    results = [
        (
            "alpine:3.10",
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-36159",
                        "PkgName": "apk-tools",
                        "Severity": "CRITICAL",
                        "CVSS": _REAL_CVSS,
                    }
                ]
            },
        )
    ]

    findings = findings_from_trivy_results(results)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "critical"
    assert finding["native_severity"] == "CRITICAL"
    assert finding["cvss_score"] == 9.1
    assert finding["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"


def test_vulnerability_finding_prefers_v3_score_over_v2() -> None:
    results = [
        (
            "alpine:3.10",
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-36159",
                        "Severity": "CRITICAL",
                        "CVSS": {"nvd": {"V2Score": 6.4, "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:P"}},
                    }
                ]
            },
        )
    ]

    findings = findings_from_trivy_results(results)

    # Falls back to v2 only when no v3 score is present at all.
    assert findings[0]["cvss_score"] == 6.4
    assert findings[0]["cvss_vector"] == "AV:N/AC:L/Au:N/C:P/I:N/A:P"


def test_vulnerability_without_cvss_omits_the_fields(tmp_path=None) -> None:
    results = [("alpine:3.10", {"Vulnerabilities": [{"VulnerabilityID": "CVE-9999-1111", "Severity": "UNKNOWN"}]})]

    findings = findings_from_trivy_results(results)

    assert "cvss_score" not in findings[0]
    assert "cvss_vector" not in findings[0]
    assert findings[0]["native_severity"] == "UNKNOWN"


def test_misconfiguration_and_secret_findings_have_no_cvss_fields() -> None:
    results = [
        (
            "deployment/app",
            {
                "Misconfigurations": [{"ID": "KSV001", "Title": "bad config", "Severity": "HIGH"}],
                "Secrets": [{"RuleID": "aws-key", "Title": "AWS key", "Severity": "CRITICAL", "Match": "AKIA***"}],
            },
        )
    ]

    findings = findings_from_trivy_results(results)

    assert len(findings) == 2
    for finding in findings:
        assert "cvss_score" not in finding
        assert "native_severity" not in finding
