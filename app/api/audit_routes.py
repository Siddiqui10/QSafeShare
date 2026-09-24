"""Audit and agent activity stream API routes."""

from fastapi import APIRouter, Query
from typing import Optional, List
from app.models.schemas import AuditLogResponse
from app.agents import audit_agent_instance

router = APIRouter(prefix="/api/audit", tags=["Audit & Agents"])


@router.get("/logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    agent: Optional[str] = Query(None),
):
    """Retrieve chronologically ordered audit logs from inter-agent interactions."""
    logs = audit_agent_instance.get_audit_trail(limit=limit, agent_filter=agent)
    return logs
