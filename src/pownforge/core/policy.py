from __future__ import annotations

from pathlib import Path

import yaml

from pownforge.core.models import Target


class PolicyError(RuntimeError):
    """Raised when a requested action falls outside the authorized scope."""


class ScopePolicy:
    def __init__(self, targets: dict[str, Target]):
        self._targets = targets

    @classmethod
    def load(cls, path: Path) -> ScopePolicy:
        if not path.exists():
            return cls(targets={})
        data = yaml.safe_load(path.read_text()) or {}
        targets = {
            name: Target(name=name, **fields)
            for name, fields in (data.get("targets") or {}).items()
        }
        return cls(targets=targets)

    def save(self, path: Path) -> None:
        data = {
            "targets": {
                name: target.model_dump(exclude={"name"}, mode="json")
                for name, target in self._targets.items()
            }
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))

    def add_target(self, target: Target) -> None:
        if target.name in self._targets:
            raise PolicyError(f"target '{target.name}' is already registered")
        self._targets[target.name] = target

    def list_targets(self) -> list[Target]:
        return list(self._targets.values())

    def resolve(self, name: str) -> Target:
        try:
            return self._targets[name]
        except KeyError as exc:
            raise PolicyError(
                f"target '{name}' is not registered; run `pownforge target add` first"
            ) from exc

    def authorize(self, name: str, plugin: str) -> Target:
        target = self.resolve(name)
        if target.allowed_plugins and plugin not in target.allowed_plugins:
            raise PolicyError(
                f"plugin '{plugin}' is not authorized for target '{name}' "
                f"(allowed: {', '.join(target.allowed_plugins)})"
            )
        return target
