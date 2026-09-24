"""Base class and messaging protocol for QSafeShare Multi-Agent Architecture."""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.database.repositories import AuditRepository


class AgentMessageEnvelope:
    """Inter-agent message protocol envelope."""

    def __init__(
        self,
        sender_agent: str,
        target_agent: str,
        action: str,
        payload: Dict[str, Any],
        correlation_id: Optional[str] = None,
    ):
        self.message_id = str(uuid.uuid4())
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.sender_agent = sender_agent
        self.target_agent = target_agent
        self.action = action
        self.payload = payload
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "sender_agent": self.sender_agent,
            "target_agent": self.target_agent,
            "action": self.action,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }


class BaseAgent:
    """Base class providing communication, identification, and audit capabilities."""

    def __init__(self, name: str, role_description: str):
        self.name = name
        self.role_description = role_description

    def log(
        self,
        action: str,
        status: str,
        details: Any,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        file_id: Optional[str] = None,
        file_name: Optional[str] = None,
    ):
        """Record an event in the system audit log."""
        AuditRepository.log_event(
            agent_name=self.name,
            action=action,
            status=status,
            details=details,
            user_id=user_id,
            username=username,
            file_id=file_id,
            file_name=file_name,
        )

    def route_message(self, target_agent: "BaseAgent", action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a typed message to another agent and log the transaction."""
        envelope = AgentMessageEnvelope(
            sender_agent=self.name,
            target_agent=target_agent.name,
            action=action,
            payload=payload,
        )
        self.log(
            action=f"MSG_DISPATCHED:{action}",
            status="INFO",
            details={"to": target_agent.name, "envelope": envelope.to_dict()},
        )
        # Execute target handler
        response = target_agent.handle_message(envelope)
        return response

    def handle_message(self, envelope: AgentMessageEnvelope) -> Dict[str, Any]:
        """Process incoming agent message. Must be implemented by subclasses."""
        raise NotImplementedError
