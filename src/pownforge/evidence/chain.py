"""Append-only hash chain over EvidenceStore's saved runs (refactor v3 §6).

Each RunRecord file already carries its own stdout/stderr hash
(`Evidence.stdout_sha256`/`stderr_sha256`, checked by
`EvidenceStore.verify()`) -- but nothing links one run's evidence to the
next, so anyone who can edit a run's JSON file can edit its embedded
hashes to match (see `EvidenceVerification`'s own documented caveat:
"this is not proof against deliberate tampering"). This adds a
lightweight, append-only chain (a simple hash chain, not a Merkle tree --
refactor v3 §6 judged a Merkle tree overkill for this) recording, for
every `EvidenceStore.save()` call (a new run OR a re-save of an existing
one, e.g. a later `add_finding()`/`review_finding()`/`result tag` call), a
hash that depends on every prior chain entry. Breaking that dependency
(secretly editing one entry without recomputing every later one) is
detectable by `verify()`; this still isn't proof against an adversary
willing to regenerate the whole chain -- see docs/handbook.md §13
"証跡チェーンの改ざん検知" for the full threat-model discussion.

Fully additive: existing per-run RunRecord JSON files are never touched
here (`EvidenceStore.save()` still writes them exactly as before); the
chain lives in a separate ledger file (`<runs_dir>/chain.jsonl`) that
simply doesn't exist for an evidence directory created before this
feature. `verify()` treats a missing ledger as "nothing to verify yet",
never as a tamper signal.
"""

from __future__ import annotations

from pathlib import Path

from pownforge.core.file_lock import flock_path
from pownforge.core.models import ChainEntry, ChainMismatch, ChainVerification
from pownforge.evidence.hashing import sha256_file, sha256_text

GENESIS_HASH = "0" * 64


class EvidenceChain:
    """Manages `<runs_dir>/chain.jsonl`. One instance per EvidenceStore
    (same `runs_dir`); the lock file lives alongside the ledger so
    `append()` is safe across concurrent callers (two ScanRunner targets,
    or the Web UI and a CLI invocation racing on the same store)."""

    def __init__(self, runs_dir: Path) -> None:
        self._runs_dir = runs_dir
        self._ledger_path = runs_dir / "chain.jsonl"
        self._lock_path = runs_dir / ".chain.lock"

    def append(self, run_id: str, record_path: Path) -> ChainEntry:
        """Append one entry for RUN_ID's current on-disk content at
        RECORD_PATH -- called by `EvidenceStore.save()` right after it
        writes that file, so `record_sha256` matches exactly what's on
        disk. Locked so two concurrent `save()` calls append in a
        well-defined, non-interleaved order (never two entries racing to
        read the same "last entry" and both claiming the same `seq`)."""
        record_sha256 = sha256_file(record_path)
        with flock_path(self._lock_path):
            last = self._last_entry()
            seq = (last.seq + 1) if last else 0
            prev_chain_hash = last.chain_hash if last else GENESIS_HASH
            chain_hash = sha256_text(prev_chain_hash + record_sha256)
            entry = ChainEntry(
                seq=seq,
                run_id=run_id,
                record_sha256=record_sha256,
                prev_chain_hash=prev_chain_hash,
                chain_hash=chain_hash,
            )
            with self._ledger_path.open("a") as handle:
                handle.write(entry.model_dump_json() + "\n")
            return entry

    def entries(self) -> list[ChainEntry]:
        if not self._ledger_path.exists():
            return []
        entries: list[ChainEntry] = []
        with self._ledger_path.open() as handle:
            for line in handle:
                line = line.strip()
                if line:
                    entries.append(ChainEntry.model_validate_json(line))
        return entries

    def _last_entry(self) -> ChainEntry | None:
        entries = self.entries()
        return entries[-1] if entries else None

    def verify(self) -> ChainVerification:
        """Two-part check: (1) the ledger itself is an unbroken chain from
        genesis (no entry inserted/reordered/edited without cascading
        through every later `chain_hash`); (2) for each run_id, its
        *latest* ledger entry matches the run's *current* on-disk content
        (earlier entries for the same run_id are legitimate history --
        e.g. the state before a later `add_finding()` -- not a mismatch,
        since nothing keeps a byte-for-byte snapshot of every past
        state, only its hash)."""
        entries = self.entries()
        mismatches: list[ChainMismatch] = []

        expected_prev = GENESIS_HASH
        for entry in entries:
            if entry.prev_chain_hash != expected_prev:
                mismatches.append(
                    ChainMismatch(
                        kind="broken_link",
                        seq=entry.seq,
                        run_id=entry.run_id,
                        detail=f"expected prev_chain_hash={expected_prev}, got {entry.prev_chain_hash}",
                    )
                )
            elif sha256_text(entry.prev_chain_hash + entry.record_sha256) != entry.chain_hash:
                mismatches.append(
                    ChainMismatch(
                        kind="broken_link",
                        seq=entry.seq,
                        run_id=entry.run_id,
                        detail="chain_hash does not match sha256(prev_chain_hash + record_sha256)",
                    )
                )
            # Keep chaining forward from this entry's own claimed
            # chain_hash even when it didn't verify, so one broken link
            # is reported once rather than cascading into every entry
            # after it.
            expected_prev = entry.chain_hash

        latest_by_run: dict[str, ChainEntry] = {}
        for entry in entries:
            latest_by_run[entry.run_id] = entry
        for run_id, entry in latest_by_run.items():
            record_path = self._runs_dir / f"{run_id}.json"
            if not record_path.exists():
                mismatches.append(
                    ChainMismatch(
                        kind="missing_file",
                        seq=entry.seq,
                        run_id=run_id,
                        detail=f"chain references run '{run_id}' but {record_path.name} no longer exists",
                    )
                )
                continue
            actual = sha256_file(record_path)
            if actual != entry.record_sha256:
                mismatches.append(
                    ChainMismatch(
                        kind="content_mismatch",
                        seq=entry.seq,
                        run_id=run_id,
                        detail=f"current file content does not match the chain's last recorded hash for '{run_id}'",
                    )
                )

        return ChainVerification(ok=not mismatches, entries_checked=len(entries), mismatches=mismatches)
