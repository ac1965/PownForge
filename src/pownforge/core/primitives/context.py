from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pownforge.core.models import Target, ValidationLevel
from pownforge.core.primitives.resources import ResourceRegistry


@dataclass
class PrimitiveContext:
    """Mutable state shared across one primitive run's lifecycle phases.
    `scratch` lets prepare() hand data to execute()/observe() without the
    primitive holding per-run state on itself (keeps primitives reusable)."""

    target: Target
    effective_level: ValidationLevel
    run_id: str
    registry: ResourceRegistry
    scratch: dict[str, Any] = field(default_factory=dict)
