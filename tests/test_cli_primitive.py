from __future__ import annotations

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pownforge.cli import app
from pownforge.evidence.primitive_store import PrimitiveRunStore

runner = CliRunner()


class _SsrfHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        from urllib.parse import parse_qs, unquote, urlparse

        url = parse_qs(urlparse(self.path).query).get("url", [None])[0]
        if url:
            try:
                urllib.request.urlopen(unquote(url), timeout=2).read()
            except Exception:
                pass
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture
def ssrf_target():
    server = HTTPServer(("127.0.0.1", 0), _SsrfHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _, port = server.server_address
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_primitive_list_shows_available() -> None:
    result = runner.invoke(app, ["primitive", "list"])
    assert result.exit_code == 0
    assert "http.oob-interaction" in result.stdout
    assert "--option path (required)" in result.stdout


def test_primitive_run_unknown_id_errors(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["primitive", "run", "java.jndi.lookup", "--target", "x", "--config", str(tmp_path / "c.yaml")],
    )
    assert result.exit_code == 1
    assert "unknown primitive" in result.stderr


def test_primitive_run_persists_and_is_listable(tmp_path: Path, ssrf_target: str) -> None:
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    assert runner.invoke(
        app,
        ["target", "add", "ssrf-lab", "--address", ssrf_target, "--kind", "url", "--config", str(config)],
    ).exit_code == 0

    run = runner.invoke(
        app,
        [
            "primitive", "run", "http.oob-interaction",
            "--target", "ssrf-lab",
            "--option", "path=/fetch?url={callback}",
            "--config", str(config),
            "--workdir", str(workdir),
        ],
    )
    assert run.exit_code == 0, run.stdout
    assert "level_reached=validation" in run.stdout
    assert "findings=1" in run.stdout

    # persisted and listable
    records = PrimitiveRunStore(workdir / "primitive_runs").list()
    assert len(records) == 1
    run_id = records[0].run_id
    assert run_id in runner.invoke(app, ["primitive", "runs", "--workdir", str(workdir)]).stdout

    show = runner.invoke(app, ["primitive", "show", run_id, "--workdir", str(workdir)])
    assert show.exit_code == 0
    assert "callback_received" in show.stdout
    assert '"confidence": "confirmed"' in show.stdout


def test_primitive_run_execution_refused_and_audited(tmp_path: Path, ssrf_target: str) -> None:
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    runner.invoke(
        app,
        ["target", "add", "ssrf-lab", "--address", ssrf_target, "--kind", "url", "--config", str(config)],
    )
    result = runner.invoke(
        app,
        [
            "primitive", "run", "http.oob-interaction",
            "--target", "ssrf-lab",
            "--option", "path=/fetch?url={callback}",
            "--level", "execution",
            "--config", str(config),
            "--workdir", str(workdir),
        ],
    )
    assert result.exit_code == 1
    assert "execution_enabled" in result.stderr
    # the refusal was recorded to the audit log
    audit = runner.invoke(app, ["audit", "list", "--workdir", str(workdir)])
    assert "primitive:http.oob-interaction" in audit.stdout


def test_primitive_report_writes_markdown_and_html(tmp_path, ssrf_target: str) -> None:
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    runner.invoke(
        app,
        ["target", "add", "ssrf-lab", "--address", ssrf_target, "--kind", "url", "--config", str(config)],
    )
    runner.invoke(
        app,
        [
            "primitive", "run", "http.oob-interaction",
            "--target", "ssrf-lab",
            "--option", "path=/fetch?url={callback}",
            "--config", str(config),
            "--workdir", str(workdir),
        ],
    )
    run_id = PrimitiveRunStore(workdir / "primitive_runs").list()[0].run_id

    for fmt, suffix, needle in [("markdown", "md", "# Primitive run"), ("html", "html", "<!doctype html>")]:
        result = runner.invoke(
            app, ["primitive", "report", run_id, "--format", fmt, "--workdir", str(workdir)]
        )
        assert result.exit_code == 0, result.stdout
        report = (workdir / "reports" / f"{run_id}.{suffix}").read_text()
        assert needle in report
        assert "callback_received" in report


def test_primitive_report_unknown_run_errors(tmp_path) -> None:
    result = runner.invoke(
        app, ["primitive", "report", "nope", "--workdir", str(tmp_path / "state")]
    )
    assert result.exit_code == 1
    assert "no primitive run" in result.stderr


def test_result_tag_add_and_remove(tmp_path, ssrf_target: str) -> None:
    from pownforge.evidence.store import EvidenceStore
    config = tmp_path / "targets.yaml"
    workdir = tmp_path / "state"
    runner.invoke(app, ["target", "add", "lab", "--address", "127.0.0.1", "--kind", "host",
                        "--allowed-plugins", "manual", "--config", str(config)])
    runner.invoke(app, ["result", "import", "--target", "lab", "--command", "x", "--output", "y",
                        "--config", str(config), "--workdir", str(workdir)])
    run_id = EvidenceStore(workdir / "runs").list()[0].run_id

    add = runner.invoke(app, ["result", "tag", run_id, "--cve", "CVE-2021-44228", "--workdir", str(workdir)])
    assert add.exit_code == 0
    assert EvidenceStore(workdir / "runs").load(run_id).cves == ["CVE-2021-44228"]

    rm = runner.invoke(app, ["result", "tag", run_id, "--cve", "CVE-2021-44228", "--remove", "--workdir", str(workdir)])
    assert rm.exit_code == 0
    assert EvidenceStore(workdir / "runs").load(run_id).cves == []
