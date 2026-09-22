from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from pownforge.core.models import PolicyViolation
from pownforge.evidence.audit import AuditStore
from pownforge.web.deps import get_audit_store

router = APIRouter(tags=["audit"])


@router.get("/audit", response_model=list[PolicyViolation])
def list_violations(audit: AuditStore = Depends(get_audit_store)) -> list[PolicyViolation]:
    return audit.list()


@router.get("/audit/{violation_id}", response_model=PolicyViolation)
def get_violation(violation_id: str, audit: AuditStore = Depends(get_audit_store)) -> PolicyViolation:
    try:
        return audit.load(violation_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
