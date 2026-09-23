"""Differential-response probe (detection + validation only).

Confirms the precondition "does controlled input change the target's
response?" by sending TWO benign requests to the same registered URL -- a
control (baseline value) and a variant (test value) -- and comparing their
responses (status code, body length, optional marker presence). A difference
indicates the input is processed/reflected server-side, which is a
*precondition* for many injection-class issues -- NOT an exploit.

It sends only the operator-supplied benign values, follows no redirects,
delivers no payload, and its highest reachable stage is VALIDATION. There is
no callback listener and nothing to clean up. Sender is injectable so the
logic is testable without real sockets.
"""

from __future__ import annotations

from dataclasses import dataclass
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
from pownforge.plugins.api import require_same_origin

_MAX_BODY_CHARS = 500_000


@dataclass
class ProbeResponse:
    status: int | None
    body: str


class ResponseSender(Protocol):
    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> ProbeResponse:
        """GET URL with HEADERS and return status + body. Transport failures
        return status=None so the comparison can still proceed."""


class UrllibResponseSender:
    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> ProbeResponse:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (lab target)
                body = resp.read(_MAX_BODY_CHARS).decode("utf-8", "replace")
                return ProbeResponse(status=resp.status, body=body)
        except urllib.error.HTTPError as exc:
            body = exc.read(_MAX_BODY_CHARS).decode("utf-8", "replace") if exc.fp else ""
            return ProbeResponse(status=exc.code, body=body)
        except Exception:
            return ProbeResponse(status=None, body="")


class ResponseDiffPrimitive(ValidationPrimitive):
    """See module docstring. Injects a probe value into the URL path
    (``{probe}`` placeholder) and/or a header, sends a control (baseline) and
    a variant request, and reports whether the responses differ."""

    def __init__(
        self,
        *,
        path: str = "/",
        header: str | None = None,
        baseline: str = "",
        variant: str,
        marker: str | None = None,
        length_threshold: int = 0,
        timeout: float = 10.0,
        sender: ResponseSender | None = None,
    ) -> None:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an absolute path starting with a single '/'")
        if "{probe}" not in path and not header:
            raise ValueError("provide an injection point: '{probe}' in path or a header name")
        if not variant:
            raise ValueError("variant (the differing test value) must not be empty")
        if length_threshold < 0:
            raise ValueError("length_threshold must be >= 0")
        self._path = path
        self._header = header
        self._baseline = baseline
        self._variant = variant
        self._marker = marker
        self._length_threshold = length_threshold
        self._timeout = timeout
        self._sender = sender or UrllibResponseSender()

    def describe(self) -> PrimitiveDescriptor:
        return PrimitiveDescriptor(
            id="http.response-diff",
            category="differential",
            description=(
                "Send a control and a variant request differing by one controlled value and report "
                "whether the target's response changes (server-side processing of input). "
                "Detection/validation only -- benign values, no payload, no code execution."
            ),
            action_class=AllowedAction.VALIDATION,
            max_level=ValidationLevel.VALIDATION,
            capabilities=[Capability.READ_ONLY],
            requires_external_network=False,
        )

    def evaluate_preconditions(self, ctx: PrimitiveContext) -> PreconditionReport:
        where = "path {probe}" if "{probe}" in self._path else ""
        if self._header:
            where = (where + f" + header {self._header}").strip(" +")
        return PreconditionReport(
            preconditions=[
                Precondition(
                    id="P1.controllable_input",
                    description="An injection point for the probe value was provided",
                    status=PreconditionStatus.MET,
                    detail=where,
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

    def _request(self, base: str, value: str) -> tuple[str, dict[str, str]]:
        path = self._path.replace("{probe}", quote(value, safe="")) if "{probe}" in self._path else self._path
        url = base.rstrip("/") + path
        require_same_origin(self.describe().id, base, url)
        headers = {self._header: value} if self._header else {}
        return url, headers

    def execute(self, ctx: PrimitiveContext) -> None:
        base = ctx.target.address
        u0, h0 = self._request(base, self._baseline)
        u1, h1 = self._request(base, self._variant)
        ctx.scratch["control"] = self._sender.fetch(u0, h0, self._timeout)
        ctx.scratch["variant"] = self._sender.fetch(u1, h1, self._timeout)
        ctx.scratch["urls"] = (u0, u1)

    def observe(self, ctx: PrimitiveContext) -> list[Observation]:
        control: ProbeResponse | None = ctx.scratch.get("control")
        variant: ProbeResponse | None = ctx.scratch.get("variant")
        if control is None or variant is None:
            return [self._observed("no_diff", "not probed (detection level)", ctx.run_id)]

        status_diff = control.status != variant.status
        len_diff = abs(len(control.body) - len(variant.body)) > self._length_threshold
        marker_diff = (
            (self._marker in control.body) != (self._marker in variant.body) if self._marker else False
        )
        differ = status_diff or len_diff or marker_diff
        ctx.scratch["differ"] = differ

        dims = ", ".join(
            d for d, on in (("status", status_diff), ("length", len_diff), ("marker", marker_diff)) if on
        )
        detail = (
            f"control(status={control.status}, len={len(control.body)}) vs "
            f"variant(status={variant.status}, len={len(variant.body)})"
            + (f"; differs by: {dims}" if differ else "; no difference")
        )
        return [self._observed("response_diff" if differ else "no_diff", detail, ctx.run_id)]

    def build_evidence(
        self, ctx: PrimitiveContext, observations: list[Observation]
    ) -> PrimitiveEvidence:
        evidence = super().build_evidence(ctx, observations)
        if not ctx.scratch.get("differ"):
            return evidence
        received = observations[0]
        evidence.findings.append(
            Finding(
                title="Controlled input changes the target response (differential response observed)",
                severity=Severity.LOW,
                detail=(
                    f"{received.detail}. Indicator only: the input is processed server-side "
                    "(a precondition for injection-class issues), not exploitation."
                ),
                source="tool",
            )
        )
        evidence.claims.append(
            Claim(
                statement=(
                    "Controlled input is processed server-side and changes the response "
                    "(precondition for injection-class issues confirmed; not exploitation)."
                ),
                confidence=ConfidenceLevel.CONFIRMED,
                supported_by=[received.id],
            )
        )
        return evidence
