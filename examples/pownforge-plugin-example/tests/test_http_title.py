from pownforge.sdk import Target, TargetKind
from pownforge.sdk.testing import assert_findings_shape, assert_plugin_contract
from pownforge_plugin_example import HttpTitlePlugin

TARGET = Target(name="lab", kind=TargetKind.URL, address="http://127.0.0.1:8000")


def test_contract() -> None:
    assert_plugin_contract(HttpTitlePlugin())


def test_normalize_extracts_title() -> None:
    result = HttpTitlePlugin().normalize(TARGET, "<html><title> Hello\n Lab </title></html>", "")
    assert result["title"] == "Hello Lab"
    assert_findings_shape(result)


def test_normalize_flags_missing_title() -> None:
    result = HttpTitlePlugin().normalize(TARGET, "<html></html>", "")
    assert result["title"] is None
    assert result["_findings"][0]["title"] == "Page has no <title>"
