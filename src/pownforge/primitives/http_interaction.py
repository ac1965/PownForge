"""Out-of-band HTTP interaction primitive (detection + callback validation).

This confirms a *precondition*, not an exploit: "given controlled input, does
the lab target make an outbound HTTP request to a lab-controlled listener?"
(the blind-SSRF / OOB-interaction class -- the same thing nuclei's interactsh
checks). It never delivers a payload, serves any class/gadget, or achieves
code execution, and its highest reachable stage is VALIDATION.

How it works: prepare() stands up a lab-local callback listener; execute()
sends the target ONE GET request whose operator-chosen field carries the
listener URL; observe() reports whether the listener was hit within a timeout.
cleanup() stops the listener and verifies the port is closed.

The listener/sender are injectable so the logic is testable without real
sockets; the defaults do real (lab-local) I/O. Both stay in-process -- this
primitive shells out to nothing (the subprocess boundary in AGENTS.md is about
external tools, which this doesn't use).
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Protocol
from urllib.parse import quote

from pownforge.core.models import (
    AllowedAction,
    Capability,
    Claim,
    ConfidenceLevel,
    Finding,
    Observation,
    Precondition,
    PreconditionReport,
    PreconditionStatus,
    PrimitiveDescriptor,
    PrimitiveEvidence,
    Severity,
    TargetKind,
    ValidationLevel,
)
from pownforge.core.operation import PrimitiveContext, ValidationPrimitive


@dataclass
class Interaction:
    """One request the callback listener received."""

    path: str
    source: str
    method: str
    timestamp: datetime


class CallbackListener(Protocol):
    def start(self) -> str:
        """Start listening; return the base URL a callback should hit."""

    def received(self, token: str, timeout: float) -> Interaction | None:
        """Return the first interaction whose path contains TOKEN, waiting up
        to TIMEOUT seconds, else None."""

    def stop(self) -> None: ...

    def verify_closed(self) -> bool:
        """Return True once the listener no longer accepts connections."""


class HttpSender(Protocol):
    def send(self, url: str, timeout: float) -> None:
        """Issue a single GET to URL. The target's own response is ignored --
        only the out-of-band callback matters -- so transport errors are
        swallowed."""


class ThreadedCallbackListener:
    """A minimal lab-local HTTP listener that records inbound requests. Binds
    to BIND_HOST on an ephemeral port; BIND_HOST must be reachable by the
    target within the lab (127.0.0.1 works for host-local targets)."""

    def __init__(self, bind_host: str = "127.0.0.1") -> None:
        self._bind_host = bind_host
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._interactions: list[Interaction] = []
        self._lock = threading.Lock()

    def start(self) -> str:
        listener = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # silence stderr logging
                pass

            def _record(self) -> None:
                with listener._lock:
                    listener._interactions.append(
                        Interaction(
                            path=self.path,
                            source=self.client_address[0],
                            method=self.command,
                            timestamp=datetime.now(timezone.utc),
                        )
                    )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _record
            do_POST = _record
            do_HEAD = _record

        self._server = HTTPServer((self._bind_host, 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._server.server_address
        return f"http://{self._bind_host}:{port}"

    def received(self, token: str, timeout: float) -> Interaction | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for interaction in self._interactions:
                    if token in interaction.path:
                        return interaction
            time.sleep(0.05)
        return None

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def verify_closed(self) -> bool:
        if self._server is not None:
            return False
        return True


class UrllibSender:
    def send(self, url: str, timeout: float) -> None:
        import urllib.request

        try:
            urllib.request.urlopen(url, timeout=timeout).read()  # noqa: S310 (lab target, http/https only)
        except Exception:
            # The target's response is irrelevant; only the callback matters.
            pass


class HttpInteractionPrimitive(ValidationPrimitive):
    """See module docstring. Constructor takes the injection point as an
    absolute path template containing '{callback}' (e.g.
    "/fetch?url={callback}") -- the single leading slash keeps the request on
    the registered target's origin. No state-changing method is used."""

    def __init__(
        self,
        path_template: str,
        *,
        bind_host: str = "127.0.0.1",
        timeout: float = 5.0,
        listener: CallbackListener | None = None,
        sender: HttpSender | None = None,
    ) -> None:
        if "{callback}" not in path_template:
            raise ValueError("path_template must contain the '{callback}' placeholder")
        if not path_template.startswith("/") or path_template.startswith("//"):
            raise ValueError("path_template must be an absolute path starting with a single '/'")
        self._path_template = path_template
        self._bind_host = bind_host
        self._timeout = timeout
        self._listener = listener
        self._sender = sender or UrllibSender()

    def describe(self) -> PrimitiveDescriptor:
        return PrimitiveDescriptor(
            id="http.oob-interaction",
            category="oob-interaction",
            description=(
                "Validate that a target makes an outbound HTTP request to a lab-controlled "
                "listener when given controlled input (blind out-of-band interaction). "
                "Detection/validation only -- no payload, no code execution."
            ),
            action_class=AllowedAction.VALIDATION,
            max_level=ValidationLevel.VALIDATION,
            capabilities=[Capability.READ_ONLY],
            # The callback is lab-internal (target -> lab listener); the primitive
            # itself needs no outbound access, so it isn't gated on that.
            requires_external_network=False,
        )

    def evaluate_preconditions(self, ctx: PrimitiveContext) -> PreconditionReport:
        return PreconditionReport(
            preconditions=[
                Precondition(
                    id="P1.controllable_input",
                    description="An input point to carry the callback URL was provided",
                    status=PreconditionStatus.MET,
                    detail=self._path_template,
                ),
                Precondition(
                    id="P2.url_target",
                    description="Target address is an HTTP(S) URL",
                    status=(
                        PreconditionStatus.MET
                        if ctx.target.kind == TargetKind.URL
                        else PreconditionStatus.UNMET
                    ),
                    detail=ctx.target.address,
                ),
            ]
        )

    def prepare(self, ctx: PrimitiveContext) -> None:
        listener = self._listener or ThreadedCallbackListener(self._bind_host)
        base = listener.start()
        token = uuid.uuid4().hex[:16]
        ctx.scratch["listener"] = listener
        ctx.scratch["token"] = token
        ctx.scratch["callback_url"] = f"{base}/{token}"
        ctx.registry.register(
            "callback-listener", description=f"lab-local OOB listener at {base}"
        )

    def execute(self, ctx: PrimitiveContext) -> None:
        callback = quote(ctx.scratch["callback_url"], safe="")
        probe_url = ctx.target.address.rstrip("/") + self._path_template.format(callback=callback)
        ctx.scratch["probe_url"] = probe_url
        self._sender.send(probe_url, self._timeout)

    def observe(self, ctx: PrimitiveContext) -> list[Observation]:
        listener: CallbackListener | None = ctx.scratch.get("listener")
        token: str = ctx.scratch.get("token", "")
        interaction = listener.received(token, self._timeout) if listener and token else None
        ctx.scratch["interaction"] = interaction

        if interaction is None:
            return [
                self._observed(
                    "callback",
                    f"no out-of-band interaction within {self._timeout:g}s "
                    f"(probe: {ctx.scratch.get('probe_url', 'not sent')})",
                    ctx.run_id,
                )
            ]
        return [
            self._observed(
                "callback_received",
                f"{interaction.method} {interaction.path} from {interaction.source} "
                f"at {interaction.timestamp.isoformat()}",
                ctx.run_id,
            )
        ]

    def build_evidence(
        self, ctx: PrimitiveContext, observations: list[Observation]
    ) -> PrimitiveEvidence:
        evidence = super().build_evidence(ctx, observations)
        if ctx.scratch.get("interaction") is None:
            return evidence
        # A callback was observed: derive the diagnostic (Finding) and the
        # higher-level assertion (Claim), each pointing back at the observed
        # fact so the observed/inferred split stays auditable.
        received = observations[0]
        evidence.findings.append(
            Finding(
                title="Out-of-band HTTP interaction confirmed (controlled input reached a listener)",
                severity=Severity.MEDIUM,
                detail=received.detail,
                source="tool",
            )
        )
        evidence.claims.append(
            Claim(
                statement=(
                    "The target makes an outbound HTTP request derived from controlled input "
                    "(out-of-band interaction precondition confirmed)."
                ),
                confidence=ConfidenceLevel.CONFIRMED,
                supported_by=[received.id],
            )
        )
        return evidence

    def cleanup(self, ctx: PrimitiveContext):
        from pownforge.core.models import CleanupResult, ResourceStatus

        listener: CallbackListener | None = ctx.scratch.get("listener")
        if listener is not None:
            listener.stop()
        results: list[CleanupResult] = []
        for resource in ctx.registry.pending_cleanup():
            ctx.registry.mark(resource.id, ResourceStatus.CLEANUP_ATTEMPTED)
            closed = listener.verify_closed() if listener is not None else True
            if closed:
                ctx.registry.mark(resource.id, ResourceStatus.VERIFIED_ABSENT)
            else:
                ctx.registry.mark(resource.id, ResourceStatus.CLEANUP_FAILED)
            results.append(
                CleanupResult(
                    resource_id=resource.id,
                    attempted=True,
                    verified_absent=closed,
                    error=None if closed else "listener still accepting connections",
                )
            )
        return results
