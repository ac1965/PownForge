from __future__ import annotations

from typing import Any

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
) -> dict[str, Any]:
    adapter = OllamaAdapter(model=body.model)
    try:
        walkthrough = generate_walkthrough(store, adapter, body.run_ids or None, body.target)
    except WalkthroughError as exc:
        # generate_walkthrough wraps an OllamaError (LLM router unavailable/
        # failed) as a WalkthroughError too; distinguish it from a plain bad
        # request (missing run_ids/target, unknown run id) via the cause.
        status = 502 if isinstance(exc.__cause__, OllamaError) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc

    # Suggestions are also embedded in the markdown/html body, but returned
    # structured too so the Web UI can render its own "AIの提案" section
    # instead of parsing it back out of the rendered text.
    result: dict[str, Any] = {"suggestions": [s.model_dump() for s in walkthrough.suggestions]}
    if body.format == "html":
        result["html"] = render_html(walkthrough)
    else:
        result["markdown"] = render_markdown(walkthrough)
    return result
