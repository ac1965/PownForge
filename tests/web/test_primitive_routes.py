from __future__ import annotations

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.web.app import create_app


def _app(tmp_path: Path):
    return create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )


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


def _register(client: TestClient, address: str) -> None:
    resp = client.post(
        "/api/targets", json={"name": "ssrf-lab", "kind": "url", "address": address}
    )
    assert resp.status_code == 201, resp.text


def test_list_primitives(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/primitives")
    assert resp.status_code == 200
    body = resp.json()
    ids = {p["descriptor"]["id"] for p in body}
    assert "http.oob-interaction" in ids
    entry = next(p for p in body if p["descriptor"]["id"] == "http.oob-interaction")
    assert entry["descriptor"]["max_level"] == "validation"
    assert any(o["name"] == "path" and o["required"] for o in entry["options"])


def test_run_persists_and_is_retrievable(tmp_path: Path, ssrf_target: str) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register(client, ssrf_target)
        run = client.post(
            "/api/primitives/run",
            json={
                "primitive": "http.oob-interaction",
                "target": "ssrf-lab",
                "options": {"path": "/fetch?url={callback}"},
            },
        )
        assert run.status_code == 201, run.text
        record = run.json()
        assert record["level_reached"] == "validation"
        assert record["evidence"]["findings"][0]["severity"] == "medium"
        assert record["evidence"]["claims"][0]["confidence"] == "confirmed"
        assert record["residual_resources"] == []

        run_id = record["run_id"]
        assert [r["run_id"] for r in client.get("/api/primitive-runs").json()] == [run_id]
        assert client.get(f"/api/primitive-runs/{run_id}").json()["run_id"] == run_id


def test_run_unknown_primitive_returns_422(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post(
            "/api/primitives/run", json={"primitive": "java.jndi.lookup", "target": "x"}
        )
    assert resp.status_code == 422
    assert "unknown primitive" in resp.json()["detail"]


def test_run_execution_beyond_safety_returns_403(tmp_path: Path, ssrf_target: str) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register(client, ssrf_target)
        resp = client.post(
            "/api/primitives/run",
            json={
                "primitive": "http.oob-interaction",
                "target": "ssrf-lab",
                "level": "execution",
                "options": {"path": "/fetch?url={callback}"},
            },
        )
    assert resp.status_code == 403
    assert "execution_enabled" in resp.json()["detail"]


def test_run_unregistered_target_returns_409(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post(
            "/api/primitives/run",
            json={
                "primitive": "http.oob-interaction",
                "target": "ghost",
                "options": {"path": "/fetch?url={callback}"},
            },
        )
    assert resp.status_code == 409
    assert "not registered" in resp.json()["detail"]


def test_reports_render_in_all_formats(tmp_path: Path, ssrf_target: str) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register(client, ssrf_target)
        run_id = client.post(
            "/api/primitives/run",
            json={
                "primitive": "http.oob-interaction",
                "target": "ssrf-lab",
                "options": {"path": "/fetch?url={callback}"},
            },
        ).json()["run_id"]

        md = client.get(f"/api/primitive-runs/{run_id}/report")
        assert "Primitive run" in md.json()["markdown"]
        html = client.get(f"/api/primitive-runs/{run_id}/report?format=html")
        assert html.json()["html"].startswith("<!doctype html>")

        pytest.importorskip("reportlab")
        pdf = client.get(f"/api/primitive-runs/{run_id}/report?format=pdf")
        assert pdf.status_code == 200
        assert pdf.headers["content-type"] == "application/pdf"
        assert pdf.content.startswith(b"%PDF-")


def test_report_unknown_run_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/primitive-runs/nope/report")
    assert resp.status_code == 404
