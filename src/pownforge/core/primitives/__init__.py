"""Validation-primitive framework: the lifecycle contract (ValidationPrimitive),
per-run state (PrimitiveContext, ResourceRegistry), and the runner that drives
a primitive under ScopePolicy/SafetyPolicy (PrimitiveRunner). Concrete
primitives (http.oob-interaction, jndi.oob-lookup-probe, ...) live in the
separate top-level `pownforge.primitives` package, not here -- this package is
the framework they implement against (refactor §5.1, "core/primitives/").

Re-exported from `pownforge.core.operation` too, for backward compatibility
with the import paths that existed before this framework was split out of
operation.py."""

from __future__ import annotations

from pownforge.core.primitives.base import ValidationPrimitive
from pownforge.core.primitives.context import PrimitiveContext
from pownforge.core.primitives.resources import ResourceRegistry
from pownforge.core.primitives.runner import PrimitiveRunner, validation_level_reaches

__all__ = [
    "PrimitiveContext",
    "PrimitiveRunner",
    "ResourceRegistry",
    "ValidationPrimitive",
    "validation_level_reaches",
]
