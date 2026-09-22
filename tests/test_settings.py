from __future__ import annotations

from pathlib import Path

from pownforge.core.settings import AppSettings, Language, load_settings, save_settings


def test_load_settings_defaults_when_file_missing(tmp_path: Path) -> None:
    settings = load_settings(tmp_path / "no-such-settings.yaml")
    assert settings.model is None
    assert settings.language == Language.JA


def test_save_then_load_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "settings.yaml"
    save_settings(AppSettings(model="claude-haiku-4.5", language=Language.EN), path)

    reloaded = load_settings(path)
    assert reloaded.model == "claude-haiku-4.5"
    assert reloaded.language == Language.EN


def test_save_settings_creates_parent_directory(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "settings.yaml"
    save_settings(AppSettings(), path)
    assert path.exists()
