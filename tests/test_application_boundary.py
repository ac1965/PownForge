"""refactor §18 step 4: Application Service functions (src/pownforge/
application/) must stay Typer/FastAPI-agnostic -- CLI and Web each
translate the domain exceptions they raise into their own exit code /
HTTP status, so the service itself must never import typer or fastapi
(which would let it raise typer.Exit/HTTPException directly). Same
pattern as test_ai_adapter_does_not_import_the_execution_layer in
test_characterization_baseline.py, for the interface boundary this
refactor introduces."""

from __future__ import annotations

import ast
from pathlib import Path

_INTERFACE_MODULES = {"typer", "fastapi", "starlette", "click"}


def test_application_service_does_not_import_typer_or_fastapi() -> None:
    application_dir = Path(__file__).resolve().parents[1] / "src" / "pownforge" / "application"
    assert application_dir.is_dir()
    offending: list[str] = []
    for path in sorted(application_dir.glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
            if module is None:
                continue
            top_level = module.split(".")[0]
            if top_level in _INTERFACE_MODULES:
                offending.append(f"{path.name}: {module}")
    assert offending == [], f"Application Service imports an interface layer: {offending}"
