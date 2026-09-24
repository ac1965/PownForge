"""Shared atomic-write helper (refactor §4.5): a Store must never leave a
partial file at its real path if the process dies mid-write. Write to a
sibling temp file in the same directory (so the final rename is on the same
filesystem, hence atomic), fsync it, then os.replace() over the destination.
A crash before the replace leaves the old file (or none) untouched; a crash
after leaves the fully-written new file. There is no state in between."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
