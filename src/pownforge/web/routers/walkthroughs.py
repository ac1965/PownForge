from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from pownforge.ai.ollama import OllamaAdapter, OllamaError
from pownforge.core.walkthrough import WalkthroughError, generate_walkthrough
from pownforge.evidence.store import EvidenceStore
from pownforge.reporting.walkthrough import render_html, render_markdown
from pownforge.web.deps import get_store

router = APIRouter(tags=["walkthroughs"])


class WalkthroughRequest(BaseModel):
    run_ids: list[str] = []
    target: str | None = None
    model: str | None = None
    format: str = "markdown"


@router.post("/walkthroughs")
def create_walkthrough(
    body: WalkthroughRequest, store: EvidenceStore = Depends(get_store)
) -> dict[str, str]:
    adapter = OllamaAdapter(model=body.model)
    try:
        walkthrough = generate_walkthrough(store, adapter, body.run_ids or None, body.target)
    except WalkthroughError as exc:
        # generate_walkthrough wraps an OllamaError (LLM router unavailable/
        # failed) as a WalkthroughError too; distinguish it from a plain bad
        # request (missing run_ids/target, unknown run id) via the cause.
        status = 502 if isinstance(exc.__cause__, OllamaError) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    if body.format == "html":
        return {"html": render_html(walkthrough)}
    return {"markdown": render_markdown(walkthrough)}
