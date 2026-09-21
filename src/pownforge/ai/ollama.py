from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

DEFAULT_LLM_BIN = Path.home() / ".local" / "bin" / "llm"


class OllamaError(RuntimeError):
    """Raised when the local LLM router cannot be invoked."""


class OllamaAdapter:
    def __init__(self, llm_bin: Path = DEFAULT_LLM_BIN, model: str | None = None) -> None:
        self._llm_bin = llm_bin
        self._model = model

    def available(self) -> bool:
        return self._llm_bin.exists() or shutil.which("llm") is not None

    def analyze(self, prompt: str) -> str:
        if not self.available():
            raise OllamaError(
                f"LLM router not found at {self._llm_bin} and 'llm' is not on PATH"
            )
        binary = str(self._llm_bin) if self._llm_bin.exists() else "llm"
        args = [binary]
        if self._model:
            args += ["-m", self._model]
        completed = subprocess.run(
            args,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if completed.returncode != 0:
            raise OllamaError(completed.stderr.strip() or "llm invocation failed")
        return completed.stdout.strip()
