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
