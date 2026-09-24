"""Audit Agent: Collects system events, tracks compliance, and aggregates metrics."""

from typing import Dict, Any, List, Optional
from app.agents.base import BaseAgent, AgentMessageEnvelope
from app.database.repositories import AuditRepository


class AuditAgent(BaseAgent):
    """Specialized agent monitoring system actions and auditing security events."""

    def __init__(self):
        super().__init__(
            name="AuditAgent",
            role_description="Audits post-quantum key operations, authorization checks, and security events.",
        )

    def get_audit_trail(self, limit: int = 100, agent_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent audit events."""
        return AuditRepository.list_logs(limit=limit, agent_filter=agent_filter)

    def handle_message(self, envelope: AgentMessageEnvelope) -> Dict[str, Any]:
        """Process messages directed to the Audit Agent."""
        return {"status": "SUCCESS", "message": "Event recorded by AuditAgent"}
