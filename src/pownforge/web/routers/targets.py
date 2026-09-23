from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from pownforge.core.models import Engagement, Target
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.web.deps import get_config_path, get_policy

router = APIRouter(tags=["targets"])


@router.get("/targets", response_model=list[Target])
def list_targets(policy: ScopePolicy = Depends(get_policy)) -> list[Target]:
    return policy.list_targets()


@router.get("/engagements", response_model=list[Engagement])
def list_engagements(policy: ScopePolicy = Depends(get_policy)) -> list[Engagement]:
    """Read-only: Engagement membership is managed via `pownforge engagement
    add` (no CLI/API for editing exists yet). Exposed here purely so the
    Campaigns page can show which targets a campaign's Engagement covers."""
    return policy.list_engagements()


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
