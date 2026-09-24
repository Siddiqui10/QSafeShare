"""Policy Agent: Responsible for authorization, access control, and policy enforcement."""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from app.agents.base import BaseAgent, AgentMessageEnvelope
from app.database.repositories import PolicyRepository, UserRepository, FileRepository


class PolicyAgent(BaseAgent):
    """Specialized agent maintaining and evaluating access policies."""

    def __init__(self):
        super().__init__(
            name="PolicyAgent",
            role_description="Evaluates user authorization, expiration, and revocation policies.",
        )

    def evaluate_access(self, file_id: str, user_id: int) -> Dict[str, Any]:
        """Evaluate if user is currently authorized to access the file."""
        auth_result = PolicyRepository.check_authorization(file_id, user_id)
        user = UserRepository.get_by_id(user_id)
        username = user["username"] if user else f"User#{user_id}"
        file_info = FileRepository.get_by_id(file_id)
        filename = file_info["original_filename"] if file_info else file_id

        # File owners always have access
        if file_info and file_info["owner_id"] == user_id:
            decision = {
                "is_authorized": True,
                "status": "ALLOWED",
                "reason": "User is the file owner.",
                "policy": None,
            }
            self.log(
                action="POLICY_EVALUATED",
                status="SUCCESS",
                details=decision,
                user_id=user_id,
                username=username,
                file_id=file_id,
                file_name=filename,
            )
            return decision

        reason_code = auth_result["reason"]
        if reason_code == "ALLOWED":
            status_desc = "SUCCESS"
            message = "Access authorized by active policy."
        elif reason_code == "REVOKED":
            status_desc = "DENIED"
            message = "Access denied: recipient has been revoked by file owner."
        elif reason_code == "EXPIRED":
            status_desc = "DENIED"
            message = "Access denied: access period has expired."
        else:
            status_desc = "DENIED"
            message = "Access denied: no authorization policy exists for this user."

        decision = {
            "is_authorized": auth_result["is_authorized"],
            "status": reason_code,
            "reason": message,
            "policy": auth_result["policy"],
        }

        self.log(
            action="POLICY_EVALUATED",
            status=status_desc,
            details=decision,
            user_id=user_id,
            username=username,
            file_id=file_id,
            file_name=filename,
        )
        return decision

    def grant_access(
        self,
        file_id: str,
        user_id: int,
        expires_in_hours: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Create or update policy granting access to a user."""
        expires_at = None
        if expires_in_hours is not None and expires_in_hours > 0:
            expiry_dt = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
            expires_at = expiry_dt.isoformat()

        policy = PolicyRepository.set_policy(file_id, user_id, status="ALLOWED", expires_at=expires_at)
        user = UserRepository.get_by_id(user_id)
        username = user["username"] if user else f"User#{user_id}"

        self.log(
            action="POLICY_ACCESS_GRANTED",
            status="SUCCESS",
            details={"expires_at": expires_at},
            user_id=user_id,
            username=username,
            file_id=file_id,
        )
        return policy

    def revoke_access(self, file_id: str, user_id: int) -> bool:
        """Revoke access for a recipient."""
        success = PolicyRepository.revoke_policy(file_id, user_id)
        user = UserRepository.get_by_id(user_id)
        username = user["username"] if user else f"User#{user_id}"

        self.log(
            action="POLICY_ACCESS_REVOKED",
            status="SUCCESS" if success else "ERROR",
            details={"revoked": success},
            user_id=user_id,
            username=username,
            file_id=file_id,
        )
        return success

    def reinstate_access(
        self,
        file_id: str,
        user_id: int,
        expires_in_hours: Optional[float] = None,
    ) -> bool:
        """Reinstate revoked access."""
        expires_at = None
        if expires_in_hours is not None and expires_in_hours > 0:
            expiry_dt = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
            expires_at = expiry_dt.isoformat()

        success = PolicyRepository.reinstate_policy(file_id, user_id, expires_at=expires_at)
        user = UserRepository.get_by_id(user_id)
        username = user["username"] if user else f"User#{user_id}"

        self.log(
            action="POLICY_ACCESS_REINSTATED",
            status="SUCCESS" if success else "ERROR",
            details={"reinstated": success, "expires_at": expires_at},
            user_id=user_id,
            username=username,
            file_id=file_id,
        )
        return success

    def handle_message(self, envelope: AgentMessageEnvelope) -> Dict[str, Any]:
        """Process messages directed to the Policy Agent."""
        action = envelope.action
        payload = envelope.payload

        if action == "EVALUATE_ACCESS":
            file_id = payload["file_id"]
            user_id = payload["user_id"]
            return self.evaluate_access(file_id, user_id)

        elif action == "GRANT_ACCESS":
            file_id = payload["file_id"]
            user_id = payload["user_id"]
            expires_in_hours = payload.get("expires_in_hours")
            policy = self.grant_access(file_id, user_id, expires_in_hours)
            return {"status": "SUCCESS", "policy": policy}

        elif action == "REVOKE_ACCESS":
            file_id = payload["file_id"]
            user_id = payload["user_id"]
            ok = self.revoke_access(file_id, user_id)
            return {"status": "SUCCESS" if ok else "ERROR", "revoked": ok}

        else:
            return {"status": "ERROR", "message": f"Unknown action '{action}'"}
