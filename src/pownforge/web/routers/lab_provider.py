from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from pownforge.application import targets as target_service
from pownforge.core.lab import LabError, LabScenario, VulhubProvider, vulhub_target_name
from pownforge.core.models import Target, TargetKind
from pownforge.core.policy import PolicyError
from pownforge.web.deps import get_config_path, get_vulhub_provider

# Kept under the /lab prefix conceptually but with its own path space; scenario
# ids contain slashes ("log4j/CVE-2021-44228"), so they travel in the request
# body/query, never as a path segment.
router = APIRouter(tags=["lab-provider"], prefix="/lab/provider")


class ScenarioRef(BaseModel):
    scenario: str


class StartRequest(BaseModel):
    scenario: str
    register_target: bool = False


class CleanupRequest(BaseModel):
    scenario: str
    purge: bool = False


class StartResult(BaseModel):
    scenario: LabScenario
    registered_target: Target | None = None
    registration_warning: str | None = None
    warning: str = (
        "This is a deliberately-vulnerable environment; its compose file may publish ports "
        "on all interfaces. Run it only on an isolated lab host."
    )


@router.get("/scenarios", response_model=list[LabScenario])
def list_scenarios(provider: VulhubProvider = Depends(get_vulhub_provider)) -> list[LabScenario]:
    try:
        return provider.list_scenarios()
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/status", response_model=LabScenario)
def scenario_status(
    scenario: str, provider: VulhubProvider = Depends(get_vulhub_provider)
) -> LabScenario:
    try:
        return provider.status(scenario)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/start", response_model=StartResult)
def start_scenario(
    body: StartRequest,
    provider: VulhubProvider = Depends(get_vulhub_provider),
    config: Path = Depends(get_config_path),
) -> StartResult:
    try:
        scenario = provider.start(body.scenario)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if not body.register_target:
        return StartResult(scenario=scenario)
    if not scenario.published_ports:
        return StartResult(
            scenario=scenario,
            registration_warning="no published ports detected; nothing to register",
        )
    port = scenario.published_ports[0]
    target = Target(
        name=vulhub_target_name(body.scenario),
        kind=TargetKind.URL,
        address=f"http://127.0.0.1:{port.host_port}",
        notes=f"vulhub scenario '{body.scenario}' (deliberately vulnerable; lifecycle via lab provider)",
    )
    try:
        target = target_service.register_target(config, target)
    except PolicyError as exc:
        return StartResult(scenario=scenario, registration_warning=str(exc))
    return StartResult(scenario=scenario, registered_target=target)


@router.post("/stop", status_code=204)
def stop_scenario(body: ScenarioRef, provider: VulhubProvider = Depends(get_vulhub_provider)) -> None:
    try:
        provider.stop(body.scenario)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/reset", response_model=LabScenario)
def reset_scenario(
    body: ScenarioRef, provider: VulhubProvider = Depends(get_vulhub_provider)
) -> LabScenario:
    try:
        return provider.reset(body.scenario)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/cleanup", status_code=204)
def cleanup_scenario(
    body: CleanupRequest,
    provider: VulhubProvider = Depends(get_vulhub_provider),
    config: Path = Depends(get_config_path),
) -> None:
    try:
        provider.cleanup(body.scenario)
    except LabError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not body.purge:
        return
    try:
        target_service.remove_target(config, vulhub_target_name(body.scenario))
    except PolicyError:
        return
