from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.web.app import create_app


def _client_with_frontend(tmp_path: Path) -> TestClient:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html><body>spa shell</body></html>")
    (dist / "app.js").write_text("console.log('hi')")

    app = create_app(config=tmp_path / "targets.yaml", workdir=tmp_path / "state", frontend_dist=dist)
    return TestClient(app)


def test_static_asset_is_served_as_is(tmp_path: Path) -> None:
    client = _client_with_frontend(tmp_path)
    resp = client.get("/app.js")
    assert resp.status_code == 200
    assert "hi" in resp.text


def test_unknown_client_route_falls_back_to_index_html(tmp_path: Path) -> None:
    # A client-side route like /runs/abc123 isn't a real file; StaticFiles
    # raises HTTPException(404) for it (this Starlette version doesn't return
    # a 404 response object), so SPAStaticFiles must catch that specifically
    # and re-serve index.html instead of letting the 404 propagate.
    client = _client_with_frontend(tmp_path)
    resp = client.get("/runs/abc123")
    assert resp.status_code == 200
    assert "spa shell" in resp.text


def test_api_routes_are_not_shadowed_by_the_frontend_mount(tmp_path: Path) -> None:
    client = _client_with_frontend(tmp_path)
    resp = client.get("/api/targets")
    assert resp.status_code == 200
    assert resp.json() == []
