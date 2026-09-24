"""Sender Agent: Responsible for file ingestion, AES-256-GCM encryption, and initiating sharing."""

import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from app.agents.base import BaseAgent, AgentMessageEnvelope
from app.crypto.symmetric import SymmetricCrypto
from app.crypto.utils import sha256_bytes, b64_encode
from app.database.repositories import FileRepository, UserRepository
from app.config import UPLOAD_DIR


class SenderAgent(BaseAgent):
    """Specialized agent acting on behalf of the data owner."""

    def __init__(self, coordinator_agent: BaseAgent):
        super().__init__(
            name="SenderAgent",
            role_description="Ingests plaintext files, generates random AES-256-GCM keys, encrypts files, and coordinates sharing.",
        )
        self.coordinator_agent = coordinator_agent

    def ingest_and_encrypt(
        self,
        owner_id: int,
        filename: str,
        file_bytes: bytes,
        mime_type: str = "application/octet-stream",
    ) -> Tuple[Dict[str, Any], bytes]:
        """Ingest raw file, compute SHA-256, encrypt with fresh AES-256-GCM key, and store.

        Returns:
            Tuple of (file_record_dict, raw_aes_file_key).
        """
        owner = UserRepository.get_by_id(owner_id)
        owner_username = owner["username"] if owner else f"User#{owner_id}"

        # 1. Compute plaintext SHA-256
        plaintext_sha256 = sha256_bytes(file_bytes)
        file_id = str(uuid.uuid4())

        # 2. Generate random AES-256-GCM key
        file_key = SymmetricCrypto.generate_file_key()

        # 3. Encrypt file using AES-256-GCM
        associated_data = f"file_id:{file_id};filename:{filename}".encode("utf-8")
        nonce, ciphertext_with_tag = SymmetricCrypto.encrypt_file_data(
            file_bytes=file_bytes,
            file_key=file_key,
            associated_data=associated_data,
        )

        # 4. Save ciphertext to disk (safe for serverless / ephemeral disks)
        stored_filename = f"{file_id}.enc"
        stored_path = UPLOAD_DIR / stored_filename
        try:
            with open(stored_path, "wb") as f:
                f.write(ciphertext_with_tag)
        except (OSError, IOError):
            pass

        # 5. Persist record in database (including encrypted_blob for serverless resilience)
        file_record = FileRepository.create_file(
            file_id=file_id,
            owner_id=owner_id,
            original_filename=filename,
            stored_path=str(stored_path),
            file_size=len(file_bytes),
            mime_type=mime_type,
            sha256_checksum=plaintext_sha256,
            encryption_algorithm="AES-256-GCM",
            file_nonce_b64=b64_encode(nonce),
            encrypted_blob=ciphertext_with_tag,
        )

        self.log(
            action="FILE_ENCRYPTED_AES256GCM",
            status="SUCCESS",
            details={
                "algorithm": "AES-256-GCM",
                "nonce_bytes": len(nonce),
                "plaintext_bytes": len(file_bytes),
                "ciphertext_bytes": len(ciphertext_with_tag),
                "sha256": plaintext_sha256,
            },
            user_id=owner_id,
            username=owner_username,
            file_id=file_id,
            file_name=filename,
        )

        # Also automatically encapsulate key package for the owner themselves
        if owner:
            self.coordinator_agent.process_sharing_request(
                file_id=file_id,
                file_key=file_key,
                recipient_users=[owner],
                expires_in_hours=None,
            )

        return file_record, file_key

    def share_file(
        self,
        owner_id: int,
        file_id: str,
        file_key: bytes,
        recipient_usernames: List[str],
        expires_in_hours: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Dispatch sharing command to Coordinator Agent."""
        owner = UserRepository.get_by_id(owner_id)
        owner_username = owner["username"] if owner else f"User#{owner_id}"

        # Resolve recipient users
        recipient_users = []
        for uname in recipient_usernames:
            user = UserRepository.get_by_username(uname)
            if user:
                recipient_users.append(user)

        self.log(
            action="SHARING_INITIATED",
            status="INFO",
            details={
                "recipients": recipient_usernames,
                "expires_in_hours": expires_in_hours,
            },
            user_id=owner_id,
            username=owner_username,
            file_id=file_id,
        )

        # Route message to Coordinator Agent
        response = self.route_message(
            target_agent=self.coordinator_agent,
            action="PROCESS_SHARE",
            payload={
                "file_id": file_id,
                "file_key_hex": file_key.hex(),
                "recipients": recipient_users,
                "expires_in_hours": expires_in_hours,
            },
        )
        return response

    def handle_message(self, envelope: AgentMessageEnvelope) -> Dict[str, Any]:
        """Handle incoming messages for the Sender Agent."""
        return {"status": "SUCCESS", "message": "SenderAgent received message"}
