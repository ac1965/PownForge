from __future__ import annotations

from pathlib import Path

from pownforge.core.models import RunRecord


class EvidenceStore:
    def __init__(self, runs_dir: Path) -> None:
        self._runs_dir = runs_dir
        self._runs_dir.mkdir(parents=True, exist_ok=True)

    def save(self, record: RunRecord) -> Path:
        path = self._runs_dir / f"{record.run_id}.json"
        path.write_text(record.model_dump_json(indent=2))
        return path

    def load(self, run_id: str) -> RunRecord:
        path = self._runs_dir / f"{run_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"no run recorded with id '{run_id}'")
        return RunRecord.model_validate_json(path.read_text())

    def list(self) -> list[RunRecord]:
        records = [
            RunRecord.model_validate_json(path.read_text())
            for path in sorted(self._runs_dir.glob("*.json"))
        ]
        return sorted(records, key=lambda r: r.created_at, reverse=True)
