"""Coordinator Agent: Orchestrates key encapsulation, distribution, and access validation."""

from typing import Dict, Any, List, Optional
from app.agents.base import BaseAgent, AgentMessageEnvelope
from app.crypto.pqc_kem import PostQuantumKEM
from app.crypto.symmetric import SymmetricCrypto
from app.crypto.utils import b64_encode
from app.database.repositories import KeyPackageRepository, UserRepository, FileRepository


class CoordinatorAgent(BaseAgent):
    """Specialized agent managing post-quantum key establishment and key distribution."""

    def __init__(self, policy_agent: BaseAgent):
        super().__init__(
            name="CoordinatorAgent",
            role_description="Orchestrates ML-KEM key encapsulation and verifies policy prior to key release.",
        )
        self.policy_agent = policy_agent

    def process_sharing_request(
        self,
        file_id: str,
        file_key: bytes,
        recipient_users: List[Dict[str, Any]],
        expires_in_hours: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Orchestrate sharing: enforce policy with PolicyAgent, then perform ML-KEM encapsulation."""
        results = []
        file_info = FileRepository.get_by_id(file_id)
        filename = file_info["original_filename"] if file_info else file_id

        for user in recipient_users:
            user_id = user["id"]
            username = user["username"]
            pub_key_pem = user["public_key_pem"]
            kem_alg = user.get("kem_algorithm", "ML-KEM-768")

            # 1. Ask Policy Agent to grant/register access
            policy_resp = self.route_message(
                target_agent=self.policy_agent,
                action="GRANT_ACCESS",
                payload={"file_id": file_id, "user_id": user_id, "expires_in_hours": expires_in_hours},
            )

            # 2. Perform ML-KEM post-quantum key encapsulation
            try:
                shared_secret, kem_ciphertext = PostQuantumKEM.encapsulate(pub_key_pem, algorithm=kem_alg)

                # 3. Derive KEK via HKDF-SHA256 and wrap AES file key
                kek = SymmetricCrypto.derive_kek(shared_secret)
                wrap_nonce, wrapped_key = SymmetricCrypto.wrap_file_key(file_key, kek)

                # 4. Store key package
                key_pkg = KeyPackageRepository.save_key_package(
                    file_id=file_id,
                    recipient_id=user_id,
                    kem_algorithm=kem_alg,
                    kem_ciphertext_b64=b64_encode(kem_ciphertext),
                    wrap_nonce_b64=b64_encode(wrap_nonce),
                    wrapped_file_key_b64=b64_encode(wrapped_key),
                )

                self.log(
                    action="KEY_ENCAPSULATED_MLKEM",
                    status="SUCCESS",
                    details={
                        "algorithm": kem_alg,
                        "ciphertext_bytes": len(kem_ciphertext),
                        "wrapped_key_bytes": len(wrapped_key),
                    },
                    user_id=user_id,
                    username=username,
                    file_id=file_id,
                    file_name=filename,
                )

                results.append({
                    "user_id": user_id,
                    "username": username,
                    "status": "SUCCESS",
                    "kem_algorithm": kem_alg,
                })
            except Exception as e:
                self.log(
                    action="KEY_ENCAPSULATION_FAILED",
                    status="ERROR",
                    details={"error": str(e)},
                    user_id=user_id,
                    username=username,
                    file_id=file_id,
                    file_name=filename,
                )
                results.append({
                    "user_id": user_id,
                    "username": username,
                    "status": "ERROR",
                    "error": str(e),
                })

        return results

    def request_key_release(self, file_id: str, user_id: int) -> Dict[str, Any]:
        """Verify recipient authorization via PolicyAgent and release key package if authorized."""
        user = UserRepository.get_by_id(user_id)
        username = user["username"] if user else f"User#{user_id}"
        file_info = FileRepository.get_by_id(file_id)
        if not file_info:
            return {"authorized": False, "status": "NOT_FOUND", "message": "File not found"}

        filename = file_info["original_filename"]

        # 1. Query Policy Agent
        auth_decision = self.route_message(
            target_agent=self.policy_agent,
            action="EVALUATE_ACCESS",
            payload={"file_id": file_id, "user_id": user_id},
        )

        if not auth_decision["is_authorized"]:
            reason_status = auth_decision["status"]
            self.log(
                action="KEY_DISTRIBUTION_REFUSED",
                status="DENIED",
                details={
                    "reason": auth_decision["reason"],
                    "policy_status": reason_status,
                },
                user_id=user_id,
                username=username,
                file_id=file_id,
                file_name=filename,
            )
            return {
                "authorized": False,
                "status": reason_status,
                "message": auth_decision["reason"],
            }

        # 2. Retrieve key package
        key_pkg = KeyPackageRepository.get_key_package(file_id, user_id)
        if not key_pkg:
            self.log(
                action="KEY_PACKAGE_NOT_FOUND",
                status="ERROR",
                details={"message": "No key package found for user"},
                user_id=user_id,
                username=username,
                file_id=file_id,
                file_name=filename,
            )
            return {
                "authorized": False,
                "status": "NO_KEY_PACKAGE",
                "message": "Key package has not been generated for this user.",
            }

        self.log(
            action="KEY_DISTRIBUTION_RELEASED",
            status="SUCCESS",
            details={
                "kem_algorithm": key_pkg["kem_algorithm"],
                "file_size": file_info["file_size"],
            },
            user_id=user_id,
            username=username,
            file_id=file_id,
            file_name=filename,
        )

        return {
            "authorized": True,
            "status": "ALLOWED",
            "key_package": key_pkg,
            "file_info": file_info,
        }

    def handle_message(self, envelope: AgentMessageEnvelope) -> Dict[str, Any]:
        """Handle incoming messages for the Coordinator Agent."""
        action = envelope.action
        payload = envelope.payload

        if action == "PROCESS_SHARE":
            file_id = payload["file_id"]
            file_key = bytes.fromhex(payload["file_key_hex"])
            recipients = payload["recipients"]
            expires_in_hours = payload.get("expires_in_hours")
            results = self.process_sharing_request(file_id, file_key, recipients, expires_in_hours)
            return {"status": "SUCCESS", "results": results}

        elif action == "REQUEST_KEY":
            file_id = payload["file_id"]
            user_id = payload["user_id"]
            return self.request_key_release(file_id, user_id)

        else:
            return {"status": "ERROR", "message": f"Unknown action '{action}'"}
