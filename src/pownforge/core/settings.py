from __future__ import annotations

from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel


class Language(str, Enum):
    JA = "ja"
    EN = "en"


_LANGUAGE_INSTRUCTIONS = {
    Language.JA: (
        "Write the narrative, summaries, titles, and rationale entirely in "
        "natural Japanese (日本語). Keep tool/plugin names and technical "
        "identifiers (e.g. CVE ids, parameter names) as-is."
    ),
    Language.EN: "Write the narrative, summaries, titles, and rationale entirely in English.",
}


def language_instruction(language: Language) -> str:
    return _LANGUAGE_INSTRUCTIONS[language]


class AppSettings(BaseModel):
    """User-local AI assistant preferences: which `llm` model to request by
    default (e.g. a local Ollama model or a hosted one like
    "claude-haiku-4.5", both routed through the same `llm` CLI -- see
    ai/ollama.py) and what language its prose output should be written in.

    Which models are installed/configured varies per machine, so this file
    follows the same gitignored-with-.example pattern as
    config/targets.yaml -- see docs/handbook.md."""

    model: str | None = None
    language: Language = Language.JA


DEFAULT_SETTINGS_PATH = Path("config/settings.yaml")


def load_settings(path: Path = DEFAULT_SETTINGS_PATH) -> AppSettings:
    if not path.exists():
        return AppSettings()
    data = yaml.safe_load(path.read_text()) or {}
    return AppSettings(**data)


def save_settings(settings: AppSettings, path: Path = DEFAULT_SETTINGS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False))
