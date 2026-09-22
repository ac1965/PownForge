from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from pownforge.core.lab import LabError, LabHost, LabManager, resolve_lab_target_address
from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError, ScopePolicy
from pownforge.web.deps import get_config_path, get_lab_manager, get_policy

router = APIRouter(tags=["lab"])


class LabHostCreate(BaseModel):
    name: str
    image: str
    env: dict[str, str] = {}
    kind: TargetKind = TargetKind.HOST
    port: int | None = None
    scheme: str = "http"
    allowed_plugins: list[str] = []
    auto_register: bool = True


class LabHostCreated(BaseModel):
    host: LabHost
    target: Target | None = None
    registration_warning: str | None = None


@router.get("/lab", response_model=list[LabHost])
def list_lab_hosts(manager: LabManager = Depends(get_lab_manager)) -> list[LabHost]:
    try:
        return manager.list()
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/lab", response_model=LabHostCreated, status_code=201)
def add_lab_host(
    body: LabHostCreate,
    manager: LabManager = Depends(get_lab_manager),
    policy: ScopePolicy = Depends(get_policy),
    config: Path = Depends(get_config_path),
) -> LabHostCreated:
    try:
        address = resolve_lab_target_address(body.name, body.kind, body.scheme, body.port)
    except LabError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        host = manager.add(body.name, body.image, body.env)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if not body.auto_register:
        return LabHostCreated(host=host)

    target = Target(
        name=body.name,
        kind=body.kind,
        address=address,
        allowed_plugins=body.allowed_plugins,
        notes="lab container on the isolated docker lab network",
    )
    try:
        policy.add_target(target)
    except PolicyError as exc:
        return LabHostCreated(host=host, registration_warning=str(exc))
    policy.save(config)
    return LabHostCreated(host=host, target=target)


@router.delete("/lab/{name}", status_code=204)
def remove_lab_host(
    name: str,
    purge: bool = False,
    manager: LabManager = Depends(get_lab_manager),
    policy: ScopePolicy = Depends(get_policy),
    config: Path = Depends(get_config_path),
) -> None:
    try:
        manager.remove(name)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if not purge:
        return
    try:
        policy.remove_target(name)
    except PolicyError:
        return
    policy.save(config)
