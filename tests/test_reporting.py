from __future__ import annotations

from pownforge.core.models import Evidence, Finding, RunRecord
from pownforge.reporting.markdown import render


def _record(**overrides) -> RunRecord:
    evidence = Evidence(
        command=["nmap", "127.0.0.1"],
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        returncode=0,
        stdout_sha256="abc",
        stderr_sha256="def",
    )
    defaults = dict(target="lab", plugin="network", evidence=evidence, output={"raw_stdout": "hi"})
    defaults.update(overrides)
    return RunRecord(**defaults)


def test_render_without_findings_or_analysis_shows_placeholders() -> None:
    output = render(_record())
    assert "_No findings recorded yet._" in output
    assert "`pownforge analyze` を実行すると" in output


def test_render_with_findings_lists_them() -> None:
    record = _record(findings=[Finding(title="Open port 3000", severity="medium", detail="ppp?")])
    output = render(record)
    assert "**[medium]** Open port 3000 — ppp?" in output


def test_render_with_analysis_shows_text_not_placeholder() -> None:
    record = _record(analysis="Looks like a dev server; no confirmed vulnerabilities.")
    output = render(record)
    assert "Looks like a dev server; no confirmed vulnerabilities." in output
    assert "`pownforge analyze` を実行すると" not in output
