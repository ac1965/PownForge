from __future__ import annotations

from pathlib import Path

import yaml

from pownforge.core.models import Engagement, Target, TargetEnvironment


class PolicyError(RuntimeError):
    """Raised when a requested action falls outside the authorized scope."""


class ScopePolicy:
    def __init__(self, targets: dict[str, Target], engagements: dict[str, Engagement] | None = None):
        self._targets = targets
        self._engagements = engagements or {}

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
        return cls(targets=targets, engagements=engagements)

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
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))

    def add_target(self, target: Target) -> None:
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
