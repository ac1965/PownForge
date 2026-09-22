from __future__ import annotations

from pathlib import Path

from pownforge.core.models import PolicyViolation


class AuditStore:
    """Persists rejected scan attempts (ScopePolicy.authorize() failures).

    Mirrors EvidenceStore's one-file-per-record layout and save/list/load
    shape so the two stay consistent and equally easy to inspect.
    """

    def __init__(self, violations_dir: Path) -> None:
        self._violations_dir = violations_dir
        self._violations_dir.mkdir(parents=True, exist_ok=True)

    def record(self, target: str, plugin: str, reason: str) -> PolicyViolation:
        violation = PolicyViolation(target=target, plugin=plugin, reason=reason)
        path = self._violations_dir / f"{violation.violation_id}.json"
        path.write_text(violation.model_dump_json(indent=2))
        return violation

    def load(self, violation_id: str) -> PolicyViolation:
        path = self._violations_dir / f"{violation_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"no policy violation recorded with id '{violation_id}'")
        return PolicyViolation.model_validate_json(path.read_text())

    def list(self) -> list[PolicyViolation]:
        violations = [
            PolicyViolation.model_validate_json(path.read_text())
            for path in sorted(self._violations_dir.glob("*.json"))
        ]
        return sorted(violations, key=lambda v: v.occurred_at, reverse=True)
