from __future__ import annotations

from pathlib import Path

from pownforge.core.models import PrimitiveRunRecord


class PrimitiveRunStore:
    """Persists PrimitiveRunRecord as one JSON file per run, mirroring
    EvidenceStore's save/load/list shape so the two stay consistent and
    equally easy to inspect. Kept separate from EvidenceStore because a
    primitive run has no command/stdout/stderr hashes to verify -- its record
    is the preconditions + 4-layer evidence + cleanup outcome (see
    docs/handbook.md §15)."""

    def __init__(self, runs_dir: Path) -> None:
        self._runs_dir = runs_dir
        self._runs_dir.mkdir(parents=True, exist_ok=True)

    def save(self, record: PrimitiveRunRecord) -> Path:
        path = self._runs_dir / f"{record.run_id}.json"
        path.write_text(record.model_dump_json(indent=2))
        return path

    def load(self, run_id: str) -> PrimitiveRunRecord:
        path = self._runs_dir / f"{run_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"no primitive run recorded with id '{run_id}'")
        return PrimitiveRunRecord.model_validate_json(path.read_text())

    def list(self) -> list[PrimitiveRunRecord]:
        records = [
            PrimitiveRunRecord.model_validate_json(path.read_text())
            for path in sorted(self._runs_dir.glob("*.json"))
        ]
        return sorted(records, key=lambda r: r.created_at, reverse=True)
