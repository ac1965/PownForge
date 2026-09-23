from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from starlette.exceptions import HTTPException
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from pownforge.web.jobs import JobManager
from pownforge.web.routers import (
    attack_sessions,
    audit,
    lab,
    lab_provider,
    playbooks,
    primitives,
    runs,
    scans,
    settings as settings_router,
    targets,
    walkthroughs,
)

# Built React SPA (see webui/). Overridable so a non-editable install or a
# custom deployment layout can point elsewhere without code changes.
DEFAULT_FRONTEND_DIST = Path(__file__).resolve().parents[3] / "webui" / "dist"
DEFAULT_SETTINGS_PATH = Path("config/settings.yaml")
DEFAULT_PLAYBOOKS_DIR = Path("config/playbooks")
DEFAULT_VULHUB_DIR = Path(os.environ.get("POWNFORGE_VULHUB_DIR", "vulhub"))


class SPAStaticFiles(StaticFiles):
    """Serves the built SPA, falling back to index.html for client-side routes
    (e.g. /runs/<id>) that don't correspond to a real static file. This
    Starlette version raises HTTPException(404) for a miss rather than
    returning a 404 response, so the fallback has to catch that, not branch
    on a status code."""

    async def get_response(self, path: str, scope: Scope):
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


def create_app(
    config: Path,
    workdir: Path,
    settings: Path | None = None,
    frontend_dist: Path | None = None,
    playbooks_dir: Path | None = None,
    vulhub_dir: Path | None = None,
) -> FastAPI:
    app = FastAPI(title="PownForge")
    app.state.config_path = config
    app.state.workdir = workdir
    app.state.settings_path = settings or DEFAULT_SETTINGS_PATH
    app.state.playbooks_dir = playbooks_dir or DEFAULT_PLAYBOOKS_DIR
    app.state.vulhub_dir = vulhub_dir or DEFAULT_VULHUB_DIR
    app.state.jobs = JobManager()

    app.include_router(targets.router, prefix="/api")
    app.include_router(lab.router, prefix="/api")
    app.include_router(lab_provider.router, prefix="/api")
    app.include_router(runs.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(playbooks.router, prefix="/api")
    app.include_router(attack_sessions.router, prefix="/api")
    app.include_router(primitives.router, prefix="/api")
    app.include_router(audit.router, prefix="/api")
    app.include_router(walkthroughs.router, prefix="/api")
    app.include_router(settings_router.router, prefix="/api")

    dist = frontend_dist or Path(os.environ.get("POWNFORGE_WEB_DIST", str(DEFAULT_FRONTEND_DIST)))
    if dist.is_dir():
        app.mount("/", SPAStaticFiles(directory=dist, html=True), name="frontend")

    return app
