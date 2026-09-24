from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import yaml

from pownforge.core.atomic_write import atomic_write_text
from pownforge.core.file_lock import flock_path
from pownforge.core.identifiers import IdentifierError, validate_identifier
from pownforge.core.models import (
    AllowedAction,
    Engagement,
    PrimitiveDescriptor,
    SafetyPolicy,
    Target,
    TargetEnvironment,
    ValidationLevel,
    validation_level_at_most,
)


class PolicyError(RuntimeError):
    """Raised when a requested action falls outside the authorized scope."""


class SafetyError(PolicyError):
    """Raised when an in-scope target is asked for an action beyond the
    SafetyPolicy envelope (e.g. EXECUTION while execution_enabled is false).
    A subclass of PolicyError so existing `except PolicyError` paths -- and
    the AuditStore recording they do -- catch it too."""


class ScopePolicy:
    def __init__(
        self,
        targets: dict[str, Target],
        engagements: dict[str, Engagement] | None = None,
        safety: SafetyPolicy | None = None,
    ):
        self._targets = targets
        self._engagements = engagements or {}
        # The action envelope layered under scope. Defaults to the
        # conservative profile (detection+validation only) when the config
        # doesn't specify one -- see SafetyPolicy.
        self._safety = safety or SafetyPolicy()

    @classmethod
    def load(cls, path: Path) -> ScopePolicy:
        if not path.exists():
            return cls(targets={})
        data = yaml.safe_load(path.read_text()) or {}
        targets = {
            name: Target(name=name, **fields)
            for name, fields in (data.get("targets") or {}).items()
        }
        engagements = {
            name: Engagement(name=name, **fields)
            for name, fields in (data.get("engagements") or {}).items()
        }
        safety = SafetyPolicy(**data["safety"]) if data.get("safety") else None
        return cls(targets=targets, engagements=engagements, safety=safety)

    def save(self, path: Path) -> None:
        data = {
            "targets": {
                name: target.model_dump(exclude={"name"}, mode="json")
                for name, target in self._targets.items()
            },
            "engagements": {
                name: engagement.model_dump(exclude={"name"}, mode="json")
                for name, engagement in self._engagements.items()
            },
            "safety": self._safety.model_dump(mode="json"),
        }
        atomic_write_text(path, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))

    @property
    def safety(self) -> SafetyPolicy:
        return self._safety

    def add_target(self, target: Target) -> None:
        try:
            validate_identifier(target.name, kind="target")
        except IdentifierError as exc:
            raise PolicyError(str(exc)) from exc
        if target.name in self._targets:
            raise PolicyError(f"target '{target.name}' is already registered")
        if target.environment == TargetEnvironment.PRODUCTION and not target.notes:
            raise PolicyError(
                f"target '{target.name}' has environment=production and requires "
                "--notes documenting the authorization/engagement reference"
            )
        self._targets[target.name] = target

    def list_targets(self) -> list[Target]:
        return list(self._targets.values())

    def remove_target(self, name: str) -> None:
        try:
            del self._targets[name]
        except KeyError as exc:
            raise PolicyError(f"target '{name}' is not registered") from exc

    def resolve(self, name: str) -> Target:
        try:
            return self._targets[name]
        except KeyError as exc:
            raise PolicyError(
                f"target '{name}' is not registered; run `pownforge target add` first"
            ) from exc

    def authorize(self, name: str, plugin: str) -> Target:
        target = self.resolve(name)
        if target.excluded:
            reason = f": {target.exclusion_reason}" if target.exclusion_reason else ""
            raise PolicyError(f"target '{name}' is excluded from scanning{reason} (run `pownforge target include` to clear it)")
        if target.allowed_plugins and plugin not in target.allowed_plugins:
            raise PolicyError(
                f"plugin '{plugin}' is not authorized for target '{name}' "
                f"(allowed: {', '.join(target.allowed_plugins)})"
            )
        return target

    def authorize_primitive(
        self, name: str, descriptor: PrimitiveDescriptor, requested_level: ValidationLevel
    ) -> tuple[Target, ValidationLevel]:
        """Authorize running a validation primitive against a target and
        return the (target, effective_level). Scope is checked first (must be
        registered and not excluded), then the SafetyPolicy envelope:

        - the primitive's action class must be in allowed_actions;
        - a primitive needing persistence/outbound is refused unless the
          matching flag is enabled;
        - the effective level is clamped to min(requested, primitive.max,
          policy.max), and reaching EXECUTION additionally requires
          execution_enabled.

        Raises SafetyError (a PolicyError) when the envelope is exceeded, so
        the caller's existing audit path records the refusal.
        """
        target = self.resolve(name)
        if target.excluded:
            reason = f": {target.exclusion_reason}" if target.exclusion_reason else ""
            raise PolicyError(
                f"target '{name}' is excluded from scanning{reason} "
                "(run `pownforge target include` to clear it)"
            )

        if descriptor.action_class not in self._safety.allowed_actions:
            allowed = ", ".join(a.value for a in self._safety.allowed_actions)
            raise SafetyError(
                f"primitive '{descriptor.id}' needs action '{descriptor.action_class.value}', "
                f"which is not in this scope's allowed_actions ({allowed})"
            )
        if descriptor.requires_persistence and not self._safety.persistence_enabled:
            raise SafetyError(
                f"primitive '{descriptor.id}' needs persistence, which this scope's "
                "SafetyPolicy disables (persistence_enabled=false)"
            )
        if descriptor.requires_external_network and not self._safety.external_network_enabled:
            raise SafetyError(
                f"primitive '{descriptor.id}' needs outbound network access, which this scope's "
                "SafetyPolicy disables (external_network_enabled=false)"
            )

        # EXECUTION is opt-in and explicit. Asking for it when the lab hasn't
        # enabled it is a refusal, not a silent downgrade to VALIDATION -- the
        # caller asked for a controlled effect specifically. Lower-level
        # requests (below) are clamped silently ("run as far as you safely
        # can"), since there's no sensitive action to withhold.
        if requested_level == ValidationLevel.EXECUTION and (
            not self._safety.execution_enabled
            or self._safety.max_validation_level != ValidationLevel.EXECUTION
        ):
            raise SafetyError(
                f"reaching EXECUTION for primitive '{descriptor.id}' requires this scope's "
                "SafetyPolicy to set execution_enabled=true and max_validation_level=execution "
                "(a dedicated-lab-only setting)"
            )
        effective = validation_level_at_most(
            validation_level_at_most(requested_level, descriptor.max_level),
            self._safety.max_validation_level,
        )
        return target, effective

    def exclude_target(self, name: str, reason: str | None = None) -> Target:
        target = self.resolve(name)
        target.excluded = True
        target.exclusion_reason = reason
        return target

    def include_target(self, name: str) -> Target:
        target = self.resolve(name)
        target.excluded = False
        target.exclusion_reason = None
        return target

    def add_engagement(self, engagement: Engagement) -> None:
        try:
            validate_identifier(engagement.name, kind="engagement")
        except IdentifierError as exc:
            raise PolicyError(str(exc)) from exc
        if engagement.name in self._engagements:
            raise PolicyError(f"engagement '{engagement.name}' is already registered")
        if not engagement.targets:
            raise PolicyError(f"engagement '{engagement.name}' must list at least one target")
        for name in engagement.targets:
            self.resolve(name)  # raises PolicyError if not a registered target
        if any(self.resolve(name).environment == TargetEnvironment.PRODUCTION for name in engagement.targets) and (
            not engagement.notes
        ):
            raise PolicyError(
                f"engagement '{engagement.name}' includes a production target and requires "
                "--notes documenting the authorization/engagement reference"
            )
        self._engagements[engagement.name] = engagement

    def list_engagements(self) -> list[Engagement]:
        return list(self._engagements.values())

    def resolve_engagement(self, name: str) -> Engagement:
        try:
            return self._engagements[name]
        except KeyError as exc:
            raise PolicyError(
                f"engagement '{name}' is not registered; run `pownforge engagement add` first"
            ) from exc

    def authorize_pivot(self, engagement_name: str, source: str, dest: str) -> tuple[Target, Target]:
        """Authorize recording that DEST was reached via/from SOURCE as part
        of ENGAGEMENT_NAME. Both names must already be registered Targets
        *and* members of that Engagement -- this grants no execution rights
        by itself (a plugin scan against DEST still needs DEST's own
        `allowed_plugins`), it only authorizes the bookkeeping relationship
        between two already-authorized targets. See
        core/manual_evidence.py::import_manual_run()."""
        engagement = self.resolve_engagement(engagement_name)
        for name in (source, dest):
            if name not in engagement.targets:
                raise PolicyError(
                    f"target '{name}' is not a member of engagement '{engagement_name}' "
                    f"(members: {', '.join(engagement.targets)})"
                )
        return self.resolve(source), self.resolve(dest)


@contextmanager
def locked_policy(path: Path) -> Iterator[ScopePolicy]:
    """Load, lock, and save PATH (targets.yaml) as one guarded
    load-mutate-save sequence, via a sibling `.<name>.lock` file (same
    helper AttackOperationStore.lock() uses; refactor §6.5). CLI and Web
    can both write this file, so a bare load()...save() pair -- the
    pattern every mutating CLI command and Web route used before this --
    can silently drop a concurrent writer's change.

    Saves only if the body completes without raising, mirroring the
    existing try/except-then-save shape at every call site: a PolicyError
    from e.g. add_target() must not persist a half-applied mutation."""
    lock_path = path.parent / f".{path.name}.lock"
    try:
        with flock_path(lock_path):
            policy = ScopePolicy.load(path)
            yield policy
            policy.save(path)
    except TimeoutError as exc:
        raise PolicyError(f"could not acquire the update lock for '{path}': {exc}") from exc
