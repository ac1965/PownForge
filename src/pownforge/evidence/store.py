from __future__ import annotations

from pathlib import Path

from pownforge.core.models import EvidenceVerification, HashCheck, RunRecord
from pownforge.evidence.hashing import sha256_text


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

    def verify(self, run_id: str) -> EvidenceVerification:
        """Recompute stdout/stderr hashes from the stored output and compare
        them against the recorded evidence hashes for a run."""
        record = self.load(run_id)
        actual_stdout = sha256_text(str(record.output.get("raw_stdout", "")))
        actual_stderr = sha256_text(str(record.output.get("raw_stderr", "")))
        stdout_check = HashCheck(
            ok=actual_stdout == record.evidence.stdout_sha256,
            expected=record.evidence.stdout_sha256,
            actual=actual_stdout,
        )
        stderr_check = HashCheck(
            ok=actual_stderr == record.evidence.stderr_sha256,
            expected=record.evidence.stderr_sha256,
            actual=actual_stderr,
        )
        return EvidenceVerification(
            run_id=run_id,
            stdout=stdout_check,
            stderr=stderr_check,
            ok=stdout_check.ok and stderr_check.ok,
        )
