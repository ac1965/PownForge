from __future__ import annotations

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


def _register_target(client: TestClient, name: str = "lab") -> None:
    resp = client.post("/api/targets", json={"name": name, "kind": "host", "address": "127.0.0.1"})
    assert resp.status_code == 201


def test_list_operations_empty_by_default(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/operations")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_and_get_operation(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.post("/api/operations", json={"name": "op-1", "objective": "lab engagement"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["objective"] == "lab engagement"
        assert body["nodes"] == []
        assert body["actions"] == []

        got = client.get("/api/operations/op-1")
        assert got.status_code == 200
        assert got.json()["name"] == "op-1"


def test_create_duplicate_operation_returns_409(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/operations", json={"name": "op-1"})
        resp = client.post("/api/operations", json={"name": "op-1"})
    assert resp.status_code == 409


def test_get_unknown_operation_returns_404(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        resp = client.get("/api/operations/nope")
    assert resp.status_code == 404


def test_add_node_and_edge(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register_target(client, "a")
        _register_target(client, "b")
        client.post("/api/operations", json={"name": "op-1"})

        resp = client.post("/api/operations/op-1/nodes", json={"node_id": "n-a", "target": "a"})
        assert resp.status_code == 201
        client.post("/api/operations/op-1/nodes", json={"node_id": "n-b", "target": "b"})

        resp = client.post(
            "/api/operations/op-1/edges",
            json={"source": "a", "destination": "b", "capabilities": ["network-pivot"]},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["edges"] == [
            {"source": "a", "destination": "b", "relationship": "reachable", "capabilities": ["network-pivot"]}
        ]


def test_add_node_rejects_unregistered_target(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.post("/api/operations", json={"name": "op-1"})
        resp = client.post("/api/operations/op-1/nodes", json={"node_id": "n-a", "target": "nope"})
    assert resp.status_code == 400


def test_add_action_cannot_set_status_or_run_id(tmp_path: Path) -> None:
    """A crafted request body including status/run_id must be ignored --
    ActionCreate doesn't define those fields, so a new action always
    starts PLANNED with no run_id (refactor §15)."""
    with TestClient(_app(tmp_path)) as client:
        _register_target(client, "a")
        client.post("/api/operations", json={"name": "op-1"})

        resp = client.post(
            "/api/operations/op-1/actions",
            json={
                "id": "a1",
                "name": "recon",
                "phase": "recon",
                "kind": "scan",
                "target": "a",
                "plugin": "network",
                "status": "completed",
                "run_id": "forged-run-id",
            },
        )
        assert resp.status_code == 201
        action = resp.json()["actions"][0]
        assert action["status"] == "planned"
        assert action["run_id"] is None


def test_add_action_scan_without_plugin_is_rejected(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register_target(client, "a")
        client.post("/api/operations", json={"name": "op-1"})
        resp = client.post(
            "/api/operations/op-1/actions",
            json={"id": "a1", "name": "x", "phase": "recon", "kind": "scan", "target": "a"},
        )
    assert resp.status_code == 400


def test_approve_and_execute_manual_action(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register_target(client, "a")
        client.post("/api/operations", json={"name": "op-1"})
        client.post(
            "/api/operations/op-1/actions",
            json={"id": "a1", "name": "manual foothold", "phase": "initial-access", "kind": "manual", "target": "a"},
        )

        resp = client.post(
            "/api/operations/op-1/actions/a1/approve", json={"approved_by": "operator", "note": "ok"}
        )
        assert resp.status_code == 200
        assert resp.json()["approvals"][0]["approved_by"] == "operator"

        resp = client.post(
            "/api/operations/op-1/actions/a1/execute",
            json={"output": "uid=0(root)", "tool": "manual-exploit"},
        )
        assert resp.status_code == 200
        action = next(a for a in resp.json()["actions"] if a["id"] == "a1")
        assert action["status"] == "completed"
        assert action["run_id"] is not None


def test_execute_unapproved_action_returns_400(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register_target(client, "a")
        client.post("/api/operations", json={"name": "op-1"})
        client.post(
            "/api/operations/op-1/actions",
            json={"id": "a1", "name": "manual foothold", "phase": "initial-access", "kind": "manual", "target": "a"},
        )

        resp = client.post("/api/operations/op-1/actions/a1/execute", json={"output": "x"})
    assert resp.status_code == 400


def test_execute_manual_action_without_output_returns_400(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register_target(client, "a")
        client.post("/api/operations", json={"name": "op-1"})
        client.post(
            "/api/operations/op-1/actions",
            json={"id": "a1", "name": "manual foothold", "phase": "initial-access", "kind": "manual", "target": "a"},
        )
        client.post("/api/operations/op-1/actions/a1/approve", json={"approved_by": "operator"})

        resp = client.post("/api/operations/op-1/actions/a1/execute", json={})
    assert resp.status_code == 400


def test_execute_rejects_unmet_requires(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        _register_target(client, "a")
        client.post("/api/operations", json={"name": "op-1"})
        client.post(
            "/api/operations/op-1/actions",
            json={
                "id": "a1",
                "name": "manual foothold",
                "phase": "initial-access",
                "kind": "manual",
                "target": "a",
                "requires": ["credential"],
            },
        )
        client.post("/api/operations/op-1/actions/a1/approve", json={"approved_by": "operator"})

        resp = client.post("/api/operations/op-1/actions/a1/execute", json={"output": "x"})
        assert resp.status_code == 400

        got = client.get("/api/operations/op-1")
        action = next(a for a in got.json()["actions"] if a["id"] == "a1")
        assert action["status"] == "approved"
