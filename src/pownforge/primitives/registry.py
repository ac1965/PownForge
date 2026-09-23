from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from pownforge.core.models import PrimitiveDescriptor
from pownforge.core.operation import ValidationPrimitive
from pownforge.primitives.http_interaction import HttpInteractionPrimitive
from pownforge.primitives.jndi_lookup import JndiLookupProbePrimitive
from pownforge.primitives.response_diff import ResponseDiffPrimitive


class PrimitiveError(RuntimeError):
    """Raised for an unknown primitive id or bad build options."""


@dataclass
class PrimitiveOption:
    name: str
    description: str
    required: bool = False


@dataclass
class PrimitiveEntry:
    # Builds a configured primitive from `--option k=v` values.
    factory: Callable[[dict[str, str]], ValidationPrimitive]
    # A throwaway instance used only to read the (option-independent)
    # descriptor for `primitive list`, keeping describe() the single source.
    sample: Callable[[], ValidationPrimitive]
    options: list[PrimitiveOption]


def _build_http_oob(options: dict[str, str]) -> ValidationPrimitive:
    path = options.get("path")
    if not path:
        raise PrimitiveError(
            "http.oob-interaction requires --option path=<absolute path containing {callback}>, "
            "e.g. --option path=/fetch?url={callback}"
        )
    kwargs: dict[str, object] = {}
    if "bind_host" in options:
        kwargs["bind_host"] = options["bind_host"]
    if "timeout" in options:
        try:
            kwargs["timeout"] = float(options["timeout"])
        except ValueError as exc:
            raise PrimitiveError("http.oob-interaction --option timeout must be a number") from exc
    try:
        return HttpInteractionPrimitive(path, **kwargs)  # type: ignore[arg-type]
    except ValueError as exc:
        raise PrimitiveError(str(exc)) from exc


def _build_jndi_probe(options: dict[str, str]) -> ValidationPrimitive:
    kwargs: dict[str, object] = {}
    for key in ("header", "path", "bind_host"):
        if key in options:
            kwargs[key] = options[key]
    if "timeout" in options:
        try:
            kwargs["timeout"] = float(options["timeout"])
        except ValueError as exc:
            raise PrimitiveError("jndi.oob-lookup-probe --option timeout must be a number") from exc
    try:
        return JndiLookupProbePrimitive(**kwargs)  # type: ignore[arg-type]
    except ValueError as exc:
        raise PrimitiveError(str(exc)) from exc


def _build_response_diff(options: dict[str, str]) -> ValidationPrimitive:
    variant = options.get("variant")
    if not variant:
        raise PrimitiveError(
            "http.response-diff requires --option variant=<test value> (the differing input)"
        )
    kwargs: dict[str, object] = {"variant": variant}
    for key in ("path", "header", "baseline", "marker"):
        if key in options:
            kwargs[key] = options[key]
    if "length_threshold" in options:
        try:
            kwargs["length_threshold"] = int(options["length_threshold"])
        except ValueError as exc:
            raise PrimitiveError("http.response-diff --option length_threshold must be an integer") from exc
    if "timeout" in options:
        try:
            kwargs["timeout"] = float(options["timeout"])
        except ValueError as exc:
            raise PrimitiveError("http.response-diff --option timeout must be a number") from exc
    try:
        return ResponseDiffPrimitive(**kwargs)  # type: ignore[arg-type]
    except ValueError as exc:
        raise PrimitiveError(str(exc)) from exc


_PRIMITIVES: dict[str, PrimitiveEntry] = {
    "http.oob-interaction": PrimitiveEntry(
        factory=_build_http_oob,
        sample=lambda: HttpInteractionPrimitive("/{callback}"),
        options=[
            PrimitiveOption("path", "Absolute path containing {callback}, e.g. /fetch?url={callback}", True),
            PrimitiveOption("bind_host", "Address the lab callback listener binds to (default 127.0.0.1)"),
            PrimitiveOption("timeout", "Seconds to wait for the callback (default 5)"),
        ],
    ),
    "jndi.oob-lookup-probe": PrimitiveEntry(
        factory=_build_jndi_probe,
        sample=lambda: JndiLookupProbePrimitive(),
        options=[
            PrimitiveOption("header", "HTTP header to carry the JNDI-lookup marker (default X-Api-Version)"),
            PrimitiveOption("path", "Absolute path to request (default /)"),
            PrimitiveOption(
                "bind_host",
                "Address the lab callback listener binds to (default 127.0.0.1). For a "
                "containerized target, use a container-reachable host address, e.g. the docker "
                "bridge gateway 172.17.0.1.",
            ),
            PrimitiveOption("timeout", "Seconds to wait for the callback (default 5)"),
        ],
    ),
    "http.response-diff": PrimitiveEntry(
        factory=_build_response_diff,
        sample=lambda: ResponseDiffPrimitive(variant="x", path="/{probe}"),
        options=[
            PrimitiveOption("variant", "The differing test value (control vs this).", True),
            PrimitiveOption("path", "Absolute path, may contain {probe} (default /)"),
            PrimitiveOption("header", "Header to carry the probe value (instead of/with {probe})"),
            PrimitiveOption("baseline", "Control value (default empty)"),
            PrimitiveOption("marker", "If set, response diff also considers this string's presence"),
            PrimitiveOption("length_threshold", "Body-length delta to ignore (default 0)"),
            PrimitiveOption("timeout", "Per-request timeout seconds (default 10)"),
        ],
    ),
}


def build_primitive(primitive_id: str, options: dict[str, str]) -> ValidationPrimitive:
    entry = _PRIMITIVES.get(primitive_id)
    if entry is None:
        raise PrimitiveError(
            f"unknown primitive '{primitive_id}' (available: {', '.join(sorted(_PRIMITIVES))})"
        )
    return entry.factory(options)


def list_primitives() -> list[tuple[PrimitiveDescriptor, list[PrimitiveOption]]]:
    return [(entry.sample().describe(), entry.options) for entry in _PRIMITIVES.values()]


def primitive_options(primitive_id: str) -> list[PrimitiveOption]:
    entry = _PRIMITIVES.get(primitive_id)
    if entry is None:
        raise PrimitiveError(f"unknown primitive '{primitive_id}'")
    return entry.options
