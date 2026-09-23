from __future__ import annotations

import re
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from pownforge.core.models import ConfidenceLevel, ResourceStatus, Severity, Target, TargetKind, ValidationLevel
from pownforge.core.operation import PrimitiveRunner
from pownforge.core.policy import ScopePolicy
from pownforge.primitives.jndi_lookup import (
    JndiLookupProbePrimitive,
    TcpInteraction,
    ThreadedTcpListener,
)


class FakeTcpListener:
    def __init__(self, *, will_receive: bool) -> None:
        self._will_receive = will_receive
        self.stopped = False

    def start(self) -> str:
        return "127.0.0.1:1389"

    def received(self, timeout: float) -> TcpInteraction | None:
        if not self._will_receive:
            return None
        return TcpInteraction(source="10.0.0.9", timestamp=datetime.now(timezone.utc))

    def stop(self) -> None:
        self.stopped = True

    def verify_closed(self) -> bool:
        return self.stopped


class RecordingSender:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    def send(self, url: str, headers: dict[str, str], timeout: float) -> None:
        self.calls.append((url, headers))


def _scope() -> ScopePolicy:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.URL, address="http://lab:8080"))
    return policy


def test_marker_is_injected_into_the_chosen_header() -> None:
    sender = RecordingSender()
    primitive = JndiLookupProbePrimitive(
        header="User-Agent", listener=FakeTcpListener(will_receive=True), sender=sender
    )
    PrimitiveRunner(_scope()).run(primitive, "lab")
    url, headers = sender.calls[0]
    assert url == "http://lab:8080/"
    assert "User-Agent" in headers
    assert re.match(r"^\$\{jndi:ldap://127\.0\.0\.1:1389/[0-9a-f]{16}\}$", headers["User-Agent"])


def test_callback_yields_finding_and_confirmed_claim() -> None:
    primitive = JndiLookupProbePrimitive(
        listener=FakeTcpListener(will_receive=True), sender=RecordingSender()
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    assert record.level_reached == ValidationLevel.VALIDATION
    ev = record.evidence
    assert [o.type for o in ev.observations] == ["callback_received"]
    assert ev.observations[0].provenance.kind.value == "observed"
    assert ev.findings[0].severity == Severity.MEDIUM
    assert "Log4Shell-class" in ev.findings[0].title
    # explicitly framed as an indicator, not exploitation
    assert "no code was executed" in ev.findings[0].detail
    assert ev.claims[0].confidence == ConfidenceLevel.CONFIRMED
    assert ev.claims[0].supported_by == [ev.observations[0].id]
    assert record.resources[0].status == ResourceStatus.VERIFIED_ABSENT


def test_no_callback_yields_no_finding() -> None:
    primitive = JndiLookupProbePrimitive(
        listener=FakeTcpListener(will_receive=False), sender=RecordingSender()
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    assert [o.type for o in record.evidence.observations] == ["callback"]
    assert record.evidence.findings == []
    assert record.evidence.claims == []


def test_rejects_bad_path_and_empty_header() -> None:
    with pytest.raises(ValueError, match="single"):
        JndiLookupProbePrimitive(path="//evil")
    with pytest.raises(ValueError, match="header"):
        JndiLookupProbePrimitive(header="  ")


def test_host_kind_target_fails_precondition() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="h", kind=TargetKind.HOST, address="host"))
    record = PrimitiveRunner(policy).run(
        JndiLookupProbePrimitive(listener=FakeTcpListener(will_receive=True), sender=RecordingSender()),
        "h",
        ValidationLevel.DETECTION,
    )
    p2 = next(p for p in record.preconditions.preconditions if p.id == "P2.url_target")
    assert p2.status.value == "unmet"


# --- one real end-to-end run over 127.0.0.1 with a JNDI-lookup simulator ---


def _make_jndi_target():
    """Local 'vulnerable' target: on any request it reads the injected header,
    extracts host:port from a ${jndi:ldap://host:port/...} marker, and opens a
    raw TCP connection to it (simulating a JNDI lookup)."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            for value in self.headers.values():
                m = re.search(r"\$\{jndi:ldap://([^/]+)/", value or "")
                if m:
                    host, _, port = m.group(1).partition(":")
                    try:
                        s = socket.create_connection((host, int(port)), timeout=2)
                        s.close()
                    except OSError:
                        pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _, port = server.server_address
    return server, f"http://127.0.0.1:{port}"


@pytest.fixture
def jndi_target():
    server, url = _make_jndi_target()
    yield url
    server.shutdown()
    server.server_close()


def test_real_end_to_end_over_loopback(tmp_path: Path, jndi_target: str) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="log4shell-lab", kind=TargetKind.URL, address=jndi_target))
    record = PrimitiveRunner(policy).run(JndiLookupProbePrimitive(timeout=5.0), "log4shell-lab")
    assert record.level_reached == ValidationLevel.VALIDATION
    assert [o.type for o in record.evidence.observations] == ["callback_received"]
    assert record.evidence.claims[0].confidence == ConfidenceLevel.CONFIRMED
    assert record.residual_resources == []


def test_threaded_tcp_listener_records_and_closes() -> None:
    listener = ThreadedTcpListener("127.0.0.1")
    endpoint = listener.start()
    host, _, port = endpoint.partition(":")
    socket.create_connection((host, int(port)), timeout=2).close()
    interaction = listener.received(timeout=2)
    assert interaction is not None
    listener.stop()
    assert listener.verify_closed() is True
