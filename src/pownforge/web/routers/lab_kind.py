from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from pownforge.core.lab import (
    KIND_DEFAULT_ALLOWED_PLUGINS,
    KindClusterManager,
    LabError,
    kind_kubeconfig_path,
)
from pownforge.application import targets as target_service
from pownforge.core.models import Target, TargetKind, TargetType
from pownforge.core.policy import PolicyError
from pownforge.web.deps import get_config_path, get_kind_manager, get_kubeconfig_dir

# kind cluster names are simple slugs (no slashes), so they travel as path
# segments here (unlike Vulhub scenario ids).
router = APIRouter(tags=["lab-kind"], prefix="/lab/kind")


class KindClusterInfo(BaseModel):
    name: str
    context: str


class KindCreateRequest(BaseModel):
    name: str
    register_target: bool = True
    allowed_plugins: list[str] = Field(default_factory=lambda: list(KIND_DEFAULT_ALLOWED_PLUGINS))


class KindCreated(BaseModel):
    cluster: KindClusterInfo
    kubeconfig_path: str
    registered_target: Target | None = None
    registration_warning: str | None = None


@router.get("", response_model=list[KindClusterInfo])
def list_kind_clusters(manager: KindClusterManager = Depends(get_kind_manager)) -> list[KindClusterInfo]:
    try:
        clusters = manager.list()
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return [KindClusterInfo(name=c.name, context=c.context) for c in clusters]


@router.post("", response_model=KindCreated, status_code=201)
def create_kind_cluster(
    body: KindCreateRequest,
    manager: KindClusterManager = Depends(get_kind_manager),
    kubeconfig_dir: Path = Depends(get_kubeconfig_dir),
    config: Path = Depends(get_config_path),
) -> KindCreated:
    kubeconfig = kind_kubeconfig_path(kubeconfig_dir, body.name)
    try:
        cluster = manager.create(body.name, kubeconfig)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    info = KindClusterInfo(name=cluster.name, context=cluster.context)
    if not body.register_target:
        return KindCreated(cluster=info, kubeconfig_path=str(kubeconfig))

    target = Target(
        name=body.name,
        kind=TargetKind.HOST,
        type=TargetType.KUBERNETES,
        address=cluster.context,
        allowed_plugins=[p.strip() for p in body.allowed_plugins if p.strip()],
        notes=f"kind cluster created via web API; KUBECONFIG={kubeconfig}",
    )
    try:
        target = target_service.register_target(config, target)
    except PolicyError as exc:
        return KindCreated(cluster=info, kubeconfig_path=str(kubeconfig), registration_warning=str(exc))
    return KindCreated(cluster=info, kubeconfig_path=str(kubeconfig), registered_target=target)


@router.delete("/{name}", status_code=204)
def delete_kind_cluster(
    name: str,
    purge: bool = False,
    manager: KindClusterManager = Depends(get_kind_manager),
    kubeconfig_dir: Path = Depends(get_kubeconfig_dir),
    config: Path = Depends(get_config_path),
) -> None:
    try:
        manager.delete(name)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    kubeconfig = kind_kubeconfig_path(kubeconfig_dir, name)
    if kubeconfig.exists():
        kubeconfig.unlink()

    if not purge:
        return
    try:
        target_service.remove_target(config, name)
    except PolicyError:
        return
