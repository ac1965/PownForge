from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    """Hash of VALUE's canonical JSON form (sorted keys, UTF-8) -- stable
    regardless of dict insertion order. Used for Evidence.result_sha256
    (core/models/evidence.py): unlike stdout_sha256, this hashes the
    plugin's actual *normalized result* (RunRecord.output), so it stays
    meaningful for a plugin like `container` (trivy) that writes its
    findings to a file via -o and leaves stdout empty -- stdout_sha256 is
    then always the hash of an empty string for that plugin, verifying
    nothing (found via the RiskForge integration PoC, docs/handbook.md
    §7/§14.0.1 in the sister repo)."""
    return sha256_text(json.dumps(value, sort_keys=True, default=str, ensure_ascii=False))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
