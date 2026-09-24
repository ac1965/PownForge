from pownforge.sdk import PluginExecution, Target, TargetKind
from pownforge.sdk.testing import assert_findings_shape, assert_plugin_contract
from pownforge_plugin_example import HttpTitlePlugin

TARGET = Target(name="lab", kind=TargetKind.URL, address="http://127.0.0.1:8000")


def _execution(tmp_path) -> PluginExecution:
    return PluginExecution(tmp_path)


def test_contract() -> None:
    assert_plugin_contract(HttpTitlePlugin())


def test_normalize_extracts_title(tmp_path) -> None:
    result = HttpTitlePlugin().normalize(
        TARGET, "<html><title> Hello\n Lab </title></html>", "", _execution(tmp_path)
    )
    assert result["title"] == "Hello Lab"
    assert_findings_shape(result)


def test_normalize_flags_missing_title(tmp_path) -> None:
    result = HttpTitlePlugin().normalize(TARGET, "<html></html>", "", _execution(tmp_path))
    assert result["title"] is None
    assert result["_findings"][0]["title"] == "Page has no <title>"
