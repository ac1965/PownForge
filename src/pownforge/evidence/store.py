from __future__ import annotations

import shutil
from pathlib import Path

from pownforge.core.atomic_write import atomic_write_text
from pownforge.core.models import Artifact, EvidenceVerification, HashCheck, RunRecord
from pownforge.evidence.hashing import sha256_file, sha256_text


class EvidenceStore:
    def __init__(self, runs_dir: Path) -> None:
        self._runs_dir = runs_dir
        self._runs_dir.mkdir(parents=True, exist_ok=True)

    def save(self, record: RunRecord) -> Path:
        path = self._runs_dir / f"{record.run_id}.json"
        atomic_write_text(path, record.model_dump_json(indent=2))
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

    def import_artifact(self, run_id: str, source: Path, description: str = "") -> Artifact:
        """Copy SOURCE into the store under artifacts/<run_id>/ and return an
        Artifact referencing it, hashed at copy time. The stored `path` is
        relative to the runs dir so the record stays portable. Used by
        `result import --artifact` to retain a human-run exploit step's proof
        (a pcap, transcript, screenshot); PownForge stores it, never produces
        it."""
        if not source.is_file():
            raise FileNotFoundError(f"artifact '{source}' does not exist or is not a file")
        dest_dir = self._runs_dir / "artifacts" / run_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / source.name
        shutil.copy2(source, dest)
        return Artifact(
            type="manual-artifact",
            description=description or source.name,
            path=str(dest.relative_to(self._runs_dir)),
            sha256=sha256_file(dest),
        )

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
