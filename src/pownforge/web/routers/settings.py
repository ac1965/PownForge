from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends

from pownforge.core.settings import AppSettings, save_settings
from pownforge.web.deps import get_app_settings, get_settings_path

router = APIRouter(tags=["settings"])


@router.get("/settings", response_model=AppSettings)
def get_settings(settings: AppSettings = Depends(get_app_settings)) -> AppSettings:
    return settings


@router.put("/settings", response_model=AppSettings)
def update_settings(
    body: AppSettings, path: Path = Depends(get_settings_path)
) -> AppSettings:
    save_settings(body, path)
    return body
