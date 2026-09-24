"""Multi-Agent Architecture Module for QSafeShare."""

from .base import BaseAgent, AgentMessageEnvelope
from .policy_agent import PolicyAgent
from .coordinator_agent import CoordinatorAgent
from .sender_agent import SenderAgent
from .audit_agent import AuditAgent

# Singleton Agent Instances
policy_agent_instance = PolicyAgent()
coordinator_agent_instance = CoordinatorAgent(policy_agent=policy_agent_instance)
sender_agent_instance = SenderAgent(coordinator_agent=coordinator_agent_instance)
audit_agent_instance = AuditAgent()

__all__ = [
    "BaseAgent",
    "AgentMessageEnvelope",
    "PolicyAgent",
    "CoordinatorAgent",
    "SenderAgent",
    "AuditAgent",
    "policy_agent_instance",
    "coordinator_agent_instance",
    "sender_agent_instance",
    "audit_agent_instance",
]
