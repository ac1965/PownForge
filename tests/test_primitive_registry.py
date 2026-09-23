from __future__ import annotations

import pytest

from pownforge.primitives.http_interaction import HttpInteractionPrimitive
from pownforge.primitives.registry import (
    PrimitiveError,
    build_primitive,
    list_primitives,
    primitive_options,
)


def test_build_known_primitive() -> None:
    primitive = build_primitive("http.oob-interaction", {"path": "/fetch?url={callback}"})
    assert isinstance(primitive, HttpInteractionPrimitive)


def test_build_unknown_primitive() -> None:
    with pytest.raises(PrimitiveError, match="unknown primitive"):
        build_primitive("java.jndi.lookup", {})


def test_build_missing_required_option() -> None:
    with pytest.raises(PrimitiveError, match="requires --option path"):
        build_primitive("http.oob-interaction", {})


def test_build_propagates_validation_errors() -> None:
    with pytest.raises(PrimitiveError, match="callback"):
        build_primitive("http.oob-interaction", {"path": "/no-placeholder"})


def test_build_rejects_bad_timeout() -> None:
    with pytest.raises(PrimitiveError, match="timeout"):
        build_primitive("http.oob-interaction", {"path": "/{callback}", "timeout": "soon"})


def test_list_primitives_exposes_descriptor_and_options() -> None:
    entries = list_primitives()
    ids = {d.id for d, _ in entries}
    assert "http.oob-interaction" in ids
    descriptor, options = next(e for e in entries if e[0].id == "http.oob-interaction")
    assert descriptor.max_level.value == "validation"
    assert any(o.name == "path" and o.required for o in options)


def test_primitive_options_unknown() -> None:
    with pytest.raises(PrimitiveError):
        primitive_options("nope")


def test_build_jndi_probe_passes_bind_host() -> None:
    primitive = build_primitive("jndi.oob-lookup-probe", {"bind_host": "172.17.0.1", "header": "X-Foo"})
    # bind_host and header reach the primitive (used at prepare/execute time)
    assert primitive._bind_host == "172.17.0.1"  # noqa: SLF001
    assert primitive._header == "X-Foo"  # noqa: SLF001


def test_jndi_probe_is_listed_with_bind_host_option() -> None:
    entries = dict((d.id, opts) for d, opts in list_primitives())
    names = {o.name for o in entries["jndi.oob-lookup-probe"]}
    assert {"header", "path", "bind_host", "timeout"} <= names
