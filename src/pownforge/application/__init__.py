"""Application Service layer (refactor §18): use-case functions CLI, Web,
and any future front-end call into instead of each re-implementing the
same wiring or business logic. Deliberately Typer/FastAPI-agnostic --
every function here raises only domain exceptions (PolicyError,
TargetPathError, ...), never typer.Exit or HTTPException."""
