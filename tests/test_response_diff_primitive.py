from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from pownforge.core.models import ConfidenceLevel, Severity, Target, TargetKind, ValidationLevel
from pownforge.core.operation import PrimitiveRunner
from pownforge.core.policy import ScopePolicy
from pownforge.primitives.response_diff import ProbeResponse, ResponseDiffPrimitive


class FakeSender:
    """Returns a canned ProbeResponse per requested URL/header value."""

    def __init__(self, responses: dict[str, ProbeResponse]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> ProbeResponse:
        self.calls.append((url, headers))
        key = url + "|" + "|".join(f"{k}={v}" for k, v in sorted(headers.items()))
        return self._responses.get(key, self._responses.get(url, ProbeResponse(200, "")))


def _scope() -> ScopePolicy:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="lab", kind=TargetKind.URL, address="http://lab:8080"))
    return policy


def test_constructor_requires_injection_point_and_variant() -> None:
    with pytest.raises(ValueError, match="injection point"):
        ResponseDiffPrimitive(variant="x", path="/")
    with pytest.raises(ValueError, match="variant"):
        ResponseDiffPrimitive(variant="", path="/{probe}")
    with pytest.raises(ValueError, match="single"):
        ResponseDiffPrimitive(variant="x", path="//evil")


def test_path_probe_substitution_and_same_origin() -> None:
    sender = FakeSender({
        "http://lab:8080/search?q=aaa": ProbeResponse(200, "no results"),
        "http://lab:8080/search?q=%27": ProbeResponse(500, "SQL error near '"),
    })
    primitive = ResponseDiffPrimitive(
        variant="'", baseline="aaa", path="/search?q={probe}", sender=sender
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    # both control and variant were requested, on the target origin
    assert sender.calls[0][0] == "http://lab:8080/search?q=aaa"
    assert sender.calls[1][0].startswith("http://lab:8080/search?q=")
    # status differs -> finding + confirmed claim
    ev = record.evidence
    assert [o.type for o in ev.observations] == ["response_diff"]
    assert ev.findings[0].severity == Severity.LOW
    assert "not exploitation" in ev.findings[0].detail
    assert ev.claims[0].confidence == ConfidenceLevel.CONFIRMED
    assert ev.claims[0].supported_by == [ev.observations[0].id]
    # response-diff creates no resources to clean up
    assert record.resources == []


def test_header_injection_diff_by_length() -> None:
    sender = FakeSender({
        "http://lab:8080/|X-Role=guest": ProbeResponse(200, "short"),
        "http://lab:8080/|X-Role=admin": ProbeResponse(200, "a much longer admin body here"),
    })
    primitive = ResponseDiffPrimitive(
        variant="admin", baseline="guest", header="X-Role", sender=sender
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    assert record.evidence.observations[0].type == "response_diff"
    assert record.evidence.claims[0].confidence == ConfidenceLevel.CONFIRMED


def test_no_diff_yields_no_finding() -> None:
    sender = FakeSender({"http://lab:8080/": ProbeResponse(200, "same")})
    primitive = ResponseDiffPrimitive(variant="b", baseline="a", header="X-Foo", sender=sender)
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    assert record.evidence.observations[0].type == "no_diff"
    assert record.evidence.findings == []
    assert record.evidence.claims == []


def test_length_threshold_suppresses_small_diffs() -> None:
    sender = FakeSender({
        "http://lab:8080/|X-Foo=a": ProbeResponse(200, "12345"),
        "http://lab:8080/|X-Foo=b": ProbeResponse(200, "123456"),  # 1 char longer
    })
    primitive = ResponseDiffPrimitive(
        variant="b", baseline="a", header="X-Foo", length_threshold=5, sender=sender
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    assert record.evidence.observations[0].type == "no_diff"


def test_marker_presence_difference_counts() -> None:
    sender = FakeSender({
        "http://lab:8080/|X-Foo=a": ProbeResponse(200, "hello world"),
        "http://lab:8080/|X-Foo=b": ProbeResponse(200, "hello world ADMIN"),
    })
    primitive = ResponseDiffPrimitive(
        variant="b", baseline="a", header="X-Foo", marker="ADMIN", length_threshold=1000, sender=sender
    )
    record = PrimitiveRunner(_scope()).run(primitive, "lab")
    assert record.evidence.observations[0].type == "response_diff"


def test_host_kind_target_fails_precondition() -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="h", kind=TargetKind.HOST, address="host"))
    primitive = ResponseDiffPrimitive(variant="x", path="/{probe}", sender=FakeSender({}))
    record = PrimitiveRunner(policy).run(primitive, "h", ValidationLevel.DETECTION)
    p2 = next(p for p in record.preconditions.preconditions if p.id == "P2.url_target")
    assert p2.status.value == "unmet"


# --- one real end-to-end run over 127.0.0.1 ---


class _EchoHandler(BaseHTTPRequestHandler):
    """Returns a body that reflects the ?q= value, so control and variant differ."""

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        from urllib.parse import parse_qs, urlparse

        q = parse_qs(urlparse(self.path).query).get("q", [""])[0]
        body = f"you searched for: {q}".encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def echo_target():
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _, port = server.server_address
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_real_end_to_end_over_loopback(tmp_path: Path, echo_target: str) -> None:
    policy = ScopePolicy(targets={})
    policy.add_target(Target(name="echo", kind=TargetKind.URL, address=echo_target))
    primitive = ResponseDiffPrimitive(
        variant="LONGER_VARIANT_VALUE", baseline="a", path="/?q={probe}", timeout=5.0
    )
    record = PrimitiveRunner(policy).run(primitive, "echo")
    assert record.level_reached == ValidationLevel.VALIDATION
    assert record.evidence.observations[0].type == "response_diff"
    assert record.evidence.claims[0].confidence == ConfidenceLevel.CONFIRMED
