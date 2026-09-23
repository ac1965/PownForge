"""Outbound JNDI-lookup probe (detection + callback validation only).

This confirms a *precondition*, not an exploit: "when a JNDI-lookup-style
marker is placed in controlled input (e.g. a logged HTTP header), does the
target make an OUTBOUND connection to a lab-controlled listener?" -- the
Log4Shell (CVE-2021-44228) class of exposure indicator, and exactly what an
out-of-band scanner (interactsh, nuclei) flags.

Crucially it is NOT an exploit and cannot achieve code execution:

- the listener is a bare TCP accept-logger. It records that a connection
  arrived and immediately closes it. It never speaks LDAP/RMI, never returns
  a reference/referral, and never serves a Java class or any payload.
- so the only thing observed is "the target tried an outbound lookup", which
  is the validation signal. Turning that into code execution (serving a
  malicious class) is the exploit step -- out of scope for this framework
  (see docs/handbook.md §15 and AGENTS.md's "PownForge自身はexploitを実行しない").

Its highest reachable stage is VALIDATION. Listener/sender are injectable so
the logic is testable without real sockets; the defaults do real lab-local
I/O and shell out to nothing (in-process).
"""

from __future__ import annotations

import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

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
class TcpInteraction:
    source: str
    timestamp: datetime


class TcpCallbackListener(Protocol):
    def start(self) -> str:
        """Start listening; return the "host:port" a lookup marker points at."""

    def received(self, timeout: float) -> TcpInteraction | None:
        """Return the first inbound connection within TIMEOUT, else None."""

    def stop(self) -> None: ...

    def verify_closed(self) -> bool: ...


class HeaderHttpSender(Protocol):
    def send(self, url: str, headers: dict[str, str], timeout: float) -> None:
        """Issue a single GET to URL with HEADERS. The target's response is
        ignored -- only the out-of-band callback matters -- so transport
        errors are swallowed."""


class ThreadedTcpListener:
    """Bare TCP accept-logger on BIND_HOST:<ephemeral>. Records the source and
    time of each inbound connection and closes it at once. Speaks no protocol
    and returns no data -- it only proves a connection was attempted."""

    def __init__(self, bind_host: str = "127.0.0.1") -> None:
        self._bind_host = bind_host
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._interactions: list[TcpInteraction] = []
        self._lock = threading.Lock()

    def start(self) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._bind_host, 0))
        sock.listen(8)
        sock.settimeout(0.2)  # so the accept loop can notice _stop
        self._sock = sock
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        host, port = sock.getsockname()
        return f"{self._bind_host}:{port}"

    def _accept_loop(self) -> None:
        while not self._stop.is_set() and self._sock is not None:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self._interactions.append(
                    TcpInteraction(source=addr[0], timestamp=datetime.now(timezone.utc))
                )
            try:
                conn.close()
            except OSError:
                pass

    def received(self, timeout: float) -> TcpInteraction | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._interactions:
                    return self._interactions[0]
            time.sleep(0.05)
        return None

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def verify_closed(self) -> bool:
        return self._sock is None


class UrllibHeaderSender:
    def send(self, url: str, headers: dict[str, str], timeout: float) -> None:
        import urllib.request

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            urllib.request.urlopen(req, timeout=timeout).read()  # noqa: S310 (lab target, http/https)
        except Exception:
            # The target's response is irrelevant; only the callback matters.
            pass


class JndiLookupProbePrimitive(ValidationPrimitive):
    """See module docstring. Injects a JNDI-lookup marker
    (``${jndi:ldap://<listener>/<token>}``) into a chosen HTTP header and
    observes whether the target connects back to the lab listener. Never
    serves a payload; VALIDATION is its ceiling."""

    def __init__(
        self,
        *,
        header: str = "X-Api-Version",
        path: str = "/",
        bind_host: str = "127.0.0.1",
        timeout: float = 5.0,
        listener: TcpCallbackListener | None = None,
        sender: HeaderHttpSender | None = None,
    ) -> None:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an absolute path starting with a single '/'")
        if not header.strip():
            raise ValueError("header name must not be empty")
        self._header = header
        self._path = path
        self._bind_host = bind_host
        self._timeout = timeout
        self._listener = listener
        self._sender = sender or UrllibHeaderSender()

    def describe(self) -> PrimitiveDescriptor:
        return PrimitiveDescriptor(
            id="jndi.oob-lookup-probe",
            category="oob-interaction",
            description=(
                "Inject a JNDI-lookup marker into a logged HTTP header and observe whether the "
                "target makes an outbound lookup to a lab listener (Log4Shell-class indicator). "
                "Detection/validation only -- the listener serves nothing, no code execution."
            ),
            action_class=AllowedAction.VALIDATION,
            max_level=ValidationLevel.VALIDATION,
            capabilities=[Capability.READ_ONLY],
            requires_external_network=False,
        )

    def evaluate_preconditions(self, ctx: PrimitiveContext) -> PreconditionReport:
        return PreconditionReport(
            preconditions=[
                Precondition(
                    id="P1.controllable_input",
                    description="A header to carry the JNDI-lookup marker was provided",
                    status=PreconditionStatus.MET,
                    detail=f"header {self._header}",
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
        listener = self._listener or ThreadedTcpListener(self._bind_host)
        endpoint = listener.start()
        token = uuid.uuid4().hex[:16]
        ctx.scratch["listener"] = listener
        # A marker that points at the lab listener, which serves nothing.
        ctx.scratch["marker"] = f"${{jndi:ldap://{endpoint}/{token}}}"
        ctx.registry.register(
            "jndi-callback-listener", description=f"lab-local TCP accept-logger at {endpoint}"
        )

    def execute(self, ctx: PrimitiveContext) -> None:
        url = ctx.target.address.rstrip("/") + self._path
        headers = {self._header: ctx.scratch["marker"]}
        ctx.scratch["probe_url"] = url
        self._sender.send(url, headers, self._timeout)

    def observe(self, ctx: PrimitiveContext) -> list[Observation]:
        listener: TcpCallbackListener | None = ctx.scratch.get("listener")
        interaction = listener.received(self._timeout) if listener else None
        ctx.scratch["interaction"] = interaction
        if interaction is None:
            return [
                self._observed(
                    "callback",
                    f"no outbound JNDI lookup within {self._timeout:g}s "
                    f"(probe: {ctx.scratch.get('probe_url', 'not sent')}, header: {self._header})",
                    ctx.run_id,
                )
            ]
        return [
            self._observed(
                "callback_received",
                f"inbound connection from {interaction.source} at {interaction.timestamp.isoformat()} "
                f"(marker injected via header {self._header})",
                ctx.run_id,
            )
        ]

    def build_evidence(
        self, ctx: PrimitiveContext, observations: list[Observation]
    ) -> PrimitiveEvidence:
        evidence = super().build_evidence(ctx, observations)
        if ctx.scratch.get("interaction") is None:
            return evidence
        received = observations[0]
        evidence.findings.append(
            Finding(
                title="Outbound JNDI lookup observed (Log4Shell-class exposure indicator)",
                severity=Severity.MEDIUM,
                detail=(
                    f"{received.detail}. Indicator only: the lab listener served no referral/class "
                    "and no code was executed -- confirm impact separately (e.g. `result import`)."
                ),
                source="tool",
            )
        )
        evidence.claims.append(
            Claim(
                statement=(
                    "Controlled input reaches a JNDI-lookup sink and the target performs an "
                    "outbound lookup (exposure to the Log4Shell class confirmed; not exploitation)."
                ),
                confidence=ConfidenceLevel.CONFIRMED,
                supported_by=[received.id],
            )
        )
        return evidence

    def cleanup(self, ctx: PrimitiveContext):
        from pownforge.core.models import CleanupResult, ResourceStatus

        listener: TcpCallbackListener | None = ctx.scratch.get("listener")
        if listener is not None:
            listener.stop()
        results: list[CleanupResult] = []
        for resource in ctx.registry.pending_cleanup():
            ctx.registry.mark(resource.id, ResourceStatus.CLEANUP_ATTEMPTED)
            closed = listener.verify_closed() if listener is not None else True
            ctx.registry.mark(
                resource.id,
                ResourceStatus.VERIFIED_ABSENT if closed else ResourceStatus.CLEANUP_FAILED,
            )
            results.append(
                CleanupResult(
                    resource_id=resource.id,
                    attempted=True,
                    verified_absent=closed,
                    error=None if closed else "listener still accepting connections",
                )
            )
        return results
