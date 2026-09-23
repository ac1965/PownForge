from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from pownforge.core.models import Target
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
    policy: ScopePolicy = Depends(get_policy),
    config: Path = Depends(get_config_path),
) -> Target:
    try:
        policy.add_target(target)
    except PolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    policy.save(config)
    return target


@router.delete("/targets/{name}", status_code=204)
def remove_target(
    name: str,
    policy: ScopePolicy = Depends(get_policy),
    config: Path = Depends(get_config_path),
) -> None:
    try:
        policy.remove_target(name)
    except PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    policy.save(config)


@router.post("/targets/{name}/exclude", response_model=Target)
def exclude_target(
    name: str,
    body: ExcludeTargetRequest,
    policy: ScopePolicy = Depends(get_policy),
    config: Path = Depends(get_config_path),
) -> Target:
    try:
        target = policy.exclude_target(name, body.reason)
    except PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    policy.save(config)
    return target


@router.post("/targets/{name}/include", response_model=Target)
def include_target(
    name: str,
    policy: ScopePolicy = Depends(get_policy),
    config: Path = Depends(get_config_path),
) -> Target:
    try:
        target = policy.include_target(name)
    except PolicyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    policy.save(config)
    return target
