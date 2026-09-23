from __future__ import annotations

import threading
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from pownforge.core.models import (
    ConfidenceLevel,
    ResourceStatus,
    Severity,
    Target,
    TargetKind,
    ValidationLevel,
)
from pownforge.core.policy import ScopePolicy
from pownforge.core.operation import PrimitiveRunner
from pownforge.primitives.http_interaction import (
    HttpInteractionPrimitive,
    Interaction,
    ThreadedCallbackListener,
)


class FakeListener:
    def __init__(self, *, will_receive: bool) -> None:
        self._will_receive = will_receive
        self.started = False
        self.stopped = False

    def start(self) -> str:
        self.started = True
        return "http://127.0.0.1:9999"

    def received(self, token: str, timeout: float) -> Interaction | None:
        if not self._will_receive:
            return None
        return Interaction(
            path=f"/{token}", source="10.0.0.5", method="GET", timestamp=datetime.now(timezone.utc)
        )

    def stop(self) -> None:
        self.stopped = True

    def verify_closed(self) -> bool:
        return self.stopped


class RecordingSender:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def send(self, url: str, timeout: float) -> None:
        self.sent.append(url)


def _scope() -> ScopePolicy:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.URL, address="http://lab:8080"))
    return policy


def test_rejects_template_without_placeholder() -> None:
    with pytest.raises(ValueError, match="callback"):
        HttpInteractionPrimitive("/fetch?url=x")


def test_rejects_template_that_leaves_the_origin() -> None:
    with pytest.raises(ValueError, match="single"):
        HttpInteractionPrimitive("//evil/{callback}")


def test_callback_received_produces_finding_and_claim() -> None:
    sender = RecordingSender()
    primitive = HttpInteractionPrimitive(
        "/fetch?url={callback}", listener=FakeListener(will_receive=True), sender=sender
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")

    assert record.level_reached == ValidationLevel.VALIDATION
    # the probe stayed on the target's origin and carried the callback
    assert sender.sent and sender.sent[0].startswith("http://lab:8080/fetch?url=")
    assert "127.0.0.1" in sender.sent[0]

    evidence = record.evidence
    assert [o.type for o in evidence.observations] == ["callback_received"]
    assert evidence.observations[0].provenance.kind.value == "observed"
    assert len(evidence.findings) == 1
    assert evidence.findings[0].severity == Severity.MEDIUM
    assert evidence.findings[0].source == "tool"
    # the claim is inferred but points back at the observed fact
    assert len(evidence.claims) == 1
    assert evidence.claims[0].confidence == ConfidenceLevel.CONFIRMED
    assert evidence.claims[0].supported_by == [evidence.observations[0].id]
    # listener was cleaned up and verified gone
    assert record.resources[0].status == ResourceStatus.VERIFIED_ABSENT
    assert record.residual_resources == []


def test_no_callback_yields_no_finding() -> None:
    primitive = HttpInteractionPrimitive(
        "/fetch?url={callback}", listener=FakeListener(will_receive=False), sender=RecordingSender()
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    evidence = record.evidence
    assert [o.type for o in evidence.observations] == ["callback"]
    assert evidence.findings == []
    assert evidence.claims == []


def test_host_kind_target_fails_precondition_and_skips_probe() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="h", kind=TargetKind.HOST, address="lab-host"))
    sender = RecordingSender()
    primitive = HttpInteractionPrimitive(
        "/fetch?url={callback}", listener=FakeListener(will_receive=True), sender=sender
    )
    # DETECTION requested so the URL-kind precondition can be reported without
    # the runner attempting a probe at all.
    record = PrimitiveRunner(policy).run(primitive, "h", ValidationLevel.DETECTION)
    p2 = next(p for p in record.preconditions.preconditions if p.id == "P2.url_target")
    assert p2.status.value == "unmet"
    assert record.level_reached == ValidationLevel.DETECTION
    assert sender.sent == []  # detection never probes


# --- one real end-to-end run over 127.0.0.1 with an SSRF-style local target ---


class _SsrfTargetHandler(BaseHTTPRequestHandler):
    """A deliberately naive local 'target': GET /fetch?url=<u> fetches <u>,
    i.e. it makes the out-of-band callback. Stands in for a lab SSRF sink."""

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        from urllib.parse import parse_qs, urlparse, unquote

        query = parse_qs(urlparse(self.path).query)
        url = query.get("url", [None])[0]
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
    server = HTTPServer(("127.0.0.1", 0), _SsrfTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_real_end_to_end_callback_over_loopback(tmp_path: Path, ssrf_target: str) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="ssrf-lab", kind=TargetKind.URL, address=ssrf_target))
    primitive = HttpInteractionPrimitive("/fetch?url={callback}", timeout=5.0)
    record = PrimitiveRunner(policy).run(primitive, "ssrf-lab")

    assert record.level_reached == ValidationLevel.VALIDATION
    assert [o.type for o in record.evidence.observations] == ["callback_received"]
    assert record.evidence.claims[0].confidence == ConfidenceLevel.CONFIRMED
    assert record.residual_resources == []


def test_threaded_listener_records_and_closes() -> None:
    listener = ThreadedCallbackListener("127.0.0.1")
    base = listener.start()
    token = "abc123"
    urllib.request.urlopen(f"{base}/{token}", timeout=2).read()
    interaction = listener.received(token, timeout=2)
    assert interaction is not None and token in interaction.path
    listener.stop()
    assert listener.verify_closed() is True
