from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from pownforge.core.finding_utils import coerce_finding
from pownforge.core.models import Finding

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


@dataclass
class AnalysisResult:
    summary: str
    findings: list[Finding] = field(default_factory=list)
    parsed: bool = True


def parse_analysis_response(text: str) -> AnalysisResult:
    """Parse the `{"summary": ..., "findings": [...]}` JSON the analyze prompt
    asks the model for. Falls back to treating the whole response as the
    summary (with no findings) when the model didn't return valid JSON —
    some local models ignore formatting instructions, and that shouldn't
    crash the command or silently discard the analysis text."""
    try:
        payload = json.loads(_extract_json_object(text))
    except ValueError:
        return AnalysisResult(summary=text.strip(), findings=[], parsed=False)

    summary = str(payload.get("summary") or "").strip() or text.strip()
    findings: list[Finding] = []
    for item in payload.get("findings") or []:
        if not isinstance(item, dict):
            continue
        finding = coerce_finding(item, source="ai")
        if finding is not None:
            findings.append(finding)
    return AnalysisResult(summary=summary, findings=findings, parsed=True)


def _extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in response")
    return text[start : end + 1]
