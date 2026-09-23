from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from pownforge.web.app import create_app


def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        config=tmp_path / "targets.yaml",
        workdir=tmp_path / "state",
        settings=tmp_path / "settings.yaml",
        frontend_dist=tmp_path / "no-such-dist",
    )
    return TestClient(app)


def test_add_list_remove_target(tmp_path: Path) -> None:
    client = _client(tmp_path)
    assert client.get("/api/targets").json() == []

    body = {"name": "lab", "kind": "host", "address": "127.0.0.1", "allowed_plugins": ["network"]}
    resp = client.post("/api/targets", json=body)
    assert resp.status_code == 201
    assert resp.json()["name"] == "lab"

    names = [t["name"] for t in client.get("/api/targets").json()]
    assert names == ["lab"]

    resp = client.delete("/api/targets/lab")
    assert resp.status_code == 204
    assert client.get("/api/targets").json() == []


def test_add_duplicate_target_returns_409(tmp_path: Path) -> None:
    client = _client(tmp_path)
    body = {"name": "lab", "kind": "host", "address": "127.0.0.1"}
    assert client.post("/api/targets", json=body).status_code == 201
    resp = client.post("/api/targets", json=body)
    assert resp.status_code == 409


def test_remove_unknown_target_returns_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.delete("/api/targets/nope")
    assert resp.status_code == 404


def test_exclude_and_include_target(tmp_path: Path) -> None:
    client = _client(tmp_path)
    client.post("/api/targets", json={"name": "lab", "kind": "host", "address": "127.0.0.1"})

    resp = client.post("/api/targets/lab/exclude", json={"reason": "maintenance window"})
    assert resp.status_code == 200
    assert resp.json()["excluded"] is True
    assert resp.json()["exclusion_reason"] == "maintenance window"

    listed = client.get("/api/targets").json()[0]
    assert listed["excluded"] is True

    resp = client.post("/api/targets/lab/include")
    assert resp.status_code == 200
    assert resp.json()["excluded"] is False
    assert resp.json()["exclusion_reason"] is None


def test_exclude_unknown_target_returns_404(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.post("/api/targets/nope/exclude", json={})
    assert resp.status_code == 404


def test_add_target_with_max_concurrent(tmp_path: Path) -> None:
    client = _client(tmp_path)
    resp = client.post(
        "/api/targets",
        json={"name": "lab", "kind": "host", "address": "127.0.0.1", "max_concurrent": 2},
    )
    assert resp.status_code == 201
    assert resp.json()["max_concurrent"] == 2
