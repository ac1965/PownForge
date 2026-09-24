from __future__ import annotations

from pathlib import Path

from pownforge.core.identifiers import IdentifierError, validate_identifier
from pownforge.core.models import AttackSession, AttackSessionStage
from pownforge.evidence.store import EvidenceStore


class AttackSessionError(RuntimeError):
    """Raised when an AttackSession can't be found, created, or extended."""


class AttackSessionStore:
    """Persists AttackSession records, one JSON file per session.

    Mirrors EvidenceStore/AuditStore's one-file-per-record layout. Lives
    under the workdir (`.pownforge/attack_sessions/`), not `config/`, since
    a session is grown incrementally over the course of an engagement (like
    runs/reports) rather than authored upfront and reviewed like a
    Playbook."""

    def __init__(self, sessions_dir: Path) -> None:
        self._sessions_dir = sessions_dir
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

    def save(self, session: AttackSession) -> Path:
        path = self._sessions_dir / f"{session.name}.json"
        path.write_text(session.model_dump_json(indent=2))
        return path

    def load(self, name: str) -> AttackSession:
        path = self._sessions_dir / f"{name}.json"
        if not path.exists():
            raise AttackSessionError(f"no attack session named '{name}'")
        return AttackSession.model_validate_json(path.read_text())

    def list(self) -> list[AttackSession]:
        sessions = [
            AttackSession.model_validate_json(path.read_text())
            for path in sorted(self._sessions_dir.glob("*.json"))
        ]
        return sorted(sessions, key=lambda s: s.name)


def create_attack_session(
    store: AttackSessionStore,
    name: str,
    description: str = "",
    engagement: str | None = None,
) -> AttackSession:
    try:
        validate_identifier(name, kind="attack session")
    except IdentifierError as exc:
        raise AttackSessionError(str(exc)) from exc
    try:
        store.load(name)
    except AttackSessionError:
        pass
    else:
        raise AttackSessionError(f"attack session '{name}' already exists")
    session = AttackSession(name=name, description=description, engagement=engagement)
    store.save(session)
    return session


def add_stage(
    store: AttackSessionStore,
    evidence: EvidenceStore,
    name: str,
    run_id: str,
    label: str = "",
) -> AttackSession:
    """Append RUN_ID (with an optional human-written LABEL) as the next
    stage of session NAME. RUN_ID must already exist in EVIDENCE -- this
    never creates a run, it only references one that already happened."""
    session = store.load(name)
    try:
        evidence.load(run_id)
    except FileNotFoundError as exc:
        raise AttackSessionError(str(exc)) from exc
    session.stages.append(AttackSessionStage(run_id=run_id, label=label))
    store.save(session)
    return session
