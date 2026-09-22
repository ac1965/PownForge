from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from pownforge.web.jobs import JobManager
from pownforge.web.routers import lab, runs, scans, targets

# Built React SPA (see webui/). Overridable so a non-editable install or a
# custom deployment layout can point elsewhere without code changes.
DEFAULT_FRONTEND_DIST = Path(__file__).resolve().parents[3] / "webui" / "dist"


class SPAStaticFiles(StaticFiles):
    """Serves the built SPA, falling back to index.html for client-side routes
    (e.g. /runs/<id>) that don't correspond to a real static file."""

    async def get_response(self, path: str, scope: Scope):
        response = await super().get_response(path, scope)
        if response.status_code == 404:
            return await super().get_response("index.html", scope)
        return response


def create_app(config: Path, workdir: Path, frontend_dist: Path | None = None) -> FastAPI:
    app = FastAPI(title="PownForge")
    app.state.config_path = config
    app.state.workdir = workdir
    app.state.jobs = JobManager()

    app.include_router(targets.router, prefix="/api")
    app.include_router(lab.router, prefix="/api")
    app.include_router(runs.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")

    dist = frontend_dist or Path(os.environ.get("POWNFORGE_WEB_DIST", str(DEFAULT_FRONTEND_DIST)))
    if dist.is_dir():
        app.mount("/", SPAStaticFiles(directory=dist, html=True), name="frontend")

    return app
