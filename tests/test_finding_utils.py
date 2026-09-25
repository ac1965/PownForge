from __future__ import annotations

from pownforge.core.finding_utils import coerce_finding
from pownforge.core.models import Finding, Severity


def test_coerce_finding_passes_through_attack_technique_ids() -> None:
    finding = coerce_finding(
        {"title": "Heartbleed", "severity": "high", "attack_technique_ids": ["T1190"]}, source="tool"
    )
    assert finding is not None
    assert finding.attack_technique_ids == ["T1190"]


def test_coerce_finding_defaults_attack_technique_ids_to_empty_list() -> None:
    finding = coerce_finding({"title": "Open port"}, source="tool")
    assert finding is not None
    assert finding.attack_technique_ids == []


def test_coerce_finding_ignores_non_list_attack_technique_ids() -> None:
    finding = coerce_finding({"title": "Open port", "attack_technique_ids": "T1190"}, source="tool")
    assert finding is not None
    assert finding.attack_technique_ids == []


def test_coerce_finding_keeps_attack_technique_ids_on_severity_fallback() -> None:
    finding = coerce_finding(
        {"title": "Weird", "severity": "not-a-real-severity", "attack_technique_ids": ["T1210"]}, source="tool"
    )
    assert finding is not None
    assert finding.severity == Severity.INFO
    assert finding.attack_technique_ids == ["T1210"]


def test_finding_without_attack_technique_ids_field_loads_unchanged() -> None:
    """Backward compatibility: existing persisted JSON (no such field at
    all) must still validate, defaulting to an empty list."""
    finding = Finding.model_validate({"title": "legacy finding", "severity": "medium"})
    assert finding.attack_technique_ids == []


def test_finding_strips_blank_attack_technique_ids() -> None:
    finding = Finding(title="x", attack_technique_ids=["T1190", "", "  ", "T1210"])
    assert finding.attack_technique_ids == ["T1190", "T1210"]


def test_coerce_finding_passes_through_common_severity_fields() -> None:
    finding = coerce_finding(
        {
            "title": "CVE-2021-36159 in apk-tools",
            "severity": "critical",
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
            "native_severity": "CRITICAL",
        },
        source="tool",
    )
    assert finding is not None
    assert finding.cvss_score == 9.1
    assert finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
    assert finding.native_severity == "CRITICAL"


def test_coerce_finding_defaults_common_severity_fields_to_none() -> None:
    finding = coerce_finding({"title": "Open port"}, source="tool")
    assert finding is not None
    assert finding.cvss_score is None
    assert finding.cvss_vector is None
    assert finding.native_severity is None


def test_coerce_finding_ignores_non_numeric_cvss_score() -> None:
    finding = coerce_finding({"title": "x", "cvss_score": "not-a-number"}, source="tool")
    assert finding is not None
    assert finding.cvss_score is None


def test_finding_rejects_out_of_range_cvss_score() -> None:
    finding = Finding(title="x", cvss_score=11.0)
    assert finding.cvss_score is None
    finding = Finding(title="x", cvss_score=-1.0)
    assert finding.cvss_score is None
    finding = Finding(title="x", cvss_score=10.0)
    assert finding.cvss_score == 10.0


def test_finding_without_common_severity_fields_loads_unchanged() -> None:
    """Backward compatibility: existing persisted JSON has none of these
    keys at all -- must still validate, defaulting to None."""
    finding = Finding.model_validate({"title": "legacy finding", "severity": "medium"})
    assert finding.cvss_score is None
    assert finding.cvss_vector is None
    assert finding.native_severity is None
