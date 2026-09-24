from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from pownforge.application import targets as target_service
from pownforge.core.models import Target, TargetPathError
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.web.deps import get_config_path, get_policy

router = APIRouter(tags=["targets"])


class ExcludeTargetRequest(BaseModel):
    reason: str | None = None


@router.get("/targets", response_model=list[Target])
def list_targets(policy: ScopePolicy = Depends(get_policy)) -> list[Target]:
    return policy.list_targets()


@router.post("/targets", response_model=Target, status_code=201)
def add_target(
    target: Target,
    config: Path = Depends(get_config_path),
) -> Target:
    try:
        target = target_service.register_target(config, target)
    except TargetPathError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except PolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return target


@router.delete("/targets/{name}", status_code=204)
def remove_target(
    name: str,
    config: Path = Depends(get_config_path),
) -> None:
    try:
        target_service.remove_target(config, name)
    except PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/targets/{name}/exclude", response_model=Target)
def exclude_target(
    name: str,
    body: ExcludeTargetRequest,
    config: Path = Depends(get_config_path),
) -> Target:
    try:
        target = target_service.exclude_target(config, name, body.reason)
    except PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return target


@router.post("/targets/{name}/include", response_model=Target)
def include_target(
    name: str,
    config: Path = Depends(get_config_path),
) -> Target:
    try:
        target = target_service.include_target(config, name)
    except PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return target
