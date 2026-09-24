"""File operations, encryption, access control, and decryption service."""

import os
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from app.agents import sender_agent_instance, coordinator_agent_instance, policy_agent_instance
from app.crypto.pqc_kem import PostQuantumKEM
from app.crypto.symmetric import SymmetricCrypto
from app.crypto.utils import b64_decode, b64_encode, sha256_bytes
from app.database.repositories import (
    FileRepository,
    UserRepository,
    PolicyRepository,
    KeyPackageRepository,
)
from app.config import UPLOAD_DIR


class FileService:
    """Coordinates file lifecycle across specialized agents and crypto engine."""

    # Temporary in-memory cache for owner's raw file key between upload and initial share,
    # or owner can unwrap file key using their own ML-KEM key package!
    @staticmethod
    def get_owner_file_key(file_id: str, owner_id: int) -> bytes:
        """Recover AES file key using owner's own ML-KEM key package."""
        owner = UserRepository.get_by_id(owner_id)
        if not owner:
            raise ValueError("Owner not found")

        key_pkg = KeyPackageRepository.get_key_package(file_id, owner_id)
        if not key_pkg:
            raise ValueError("Owner key package not found")

        # Decapsulate using owner's private key
        kem_alg = key_pkg["kem_algorithm"]
        kem_ciphertext = b64_decode(key_pkg["kem_ciphertext_b64"])
        shared_secret = PostQuantumKEM.decapsulate(
            private_key_pem=owner["private_key_pem"],
            ciphertext=kem_ciphertext,
            algorithm=kem_alg,
        )

        kek = SymmetricCrypto.derive_kek(shared_secret)
        wrap_nonce = b64_decode(key_pkg["wrap_nonce_b64"])
        wrapped_key = b64_decode(key_pkg["wrapped_file_key_b64"])
        file_key = SymmetricCrypto.unwrap_file_key(wrapped_key, wrap_nonce, kek)
        return file_key

    @staticmethod
    def upload_and_encrypt(
        owner_id: int,
        filename: str,
        file_bytes: bytes,
        mime_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        """Ingest plaintext file and encrypt via Sender Agent."""
        file_record, file_key = sender_agent_instance.ingest_and_encrypt(
            owner_id=owner_id,
            filename=filename,
            file_bytes=file_bytes,
            mime_type=mime_type,
        )
        return file_record

    @staticmethod
    def share_file(
        owner_id: int,
        file_id: str,
        recipient_usernames: List[str],
        expires_in_hours: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Share an encrypted file with specified recipients."""
        file_info = FileRepository.get_by_id(file_id)
        if not file_info:
            raise ValueError("File not found")
        if file_info["owner_id"] != owner_id:
            raise PermissionError("Only the file owner can grant or share access.")

        # Recover file key using owner's key package
        file_key = FileService.get_owner_file_key(file_id, owner_id)

        # Resolve recipients
        recipients = []
        for username in recipient_usernames:
            user = UserRepository.get_by_username(username)
            if user:
                recipients.append(user)

        # Dispatch sharing to Coordinator Agent
        results = coordinator_agent_instance.process_sharing_request(
            file_id=file_id,
            file_key=file_key,
            recipient_users=recipients,
            expires_in_hours=expires_in_hours,
        )
        return results

    @staticmethod
    def revoke_recipient_access(owner_id: int, file_id: str, recipient_username: str) -> bool:
        """Revoke a user's access via Policy Agent."""
        file_info = FileRepository.get_by_id(file_id)
        if not file_info:
            raise ValueError("File not found")
        if file_info["owner_id"] != owner_id:
            raise PermissionError("Only the file owner can revoke access.")

        recipient = UserRepository.get_by_username(recipient_username)
        if not recipient:
            raise ValueError(f"Recipient '{recipient_username}' not found")

        return policy_agent_instance.revoke_access(file_id, recipient["id"])

    @staticmethod
    def reinstate_recipient_access(
        owner_id: int,
        file_id: str,
        recipient_username: str,
        expires_in_hours: Optional[float] = None,
    ) -> bool:
        """Reinstate a previously revoked recipient via Policy Agent."""
        file_info = FileRepository.get_by_id(file_id)
        if not file_info:
            raise ValueError("File not found")
        if file_info["owner_id"] != owner_id:
            raise PermissionError("Only the file owner can reinstate access.")

        recipient = UserRepository.get_by_username(recipient_username)
        if not recipient:
            raise ValueError(f"Recipient '{recipient_username}' not found")

        return policy_agent_instance.reinstate_access(
            file_id=file_id,
            user_id=recipient["id"],
            expires_in_hours=expires_in_hours,
        )

    @staticmethod
    def request_file_package(file_id: str, user_id: int) -> Dict[str, Any]:
        """Request file and key package from Coordinator Agent (subject to policy check)."""
        response = coordinator_agent_instance.request_key_release(file_id, user_id)
        return response

    @staticmethod
    def decrypt_and_verify(
        file_id: str,
        user_id: int,
        provided_private_key_pem: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Full Post-Quantum decapsulation, AES decryption, and SHA-256 verification."""
        t_start = time.perf_counter()

        # 1. Ask Coordinator Agent for key package and file info
        pkg_resp = coordinator_agent_instance.request_key_release(file_id, user_id)
        if not pkg_resp["authorized"]:
            return {
                "verified": False,
                "status": pkg_resp["status"],
                "message": pkg_resp["message"],
                "file_id": file_id,
            }

        key_pkg = pkg_resp["key_package"]
        file_info = pkg_resp["file_info"]

        # 2. Identify private key
        if provided_private_key_pem:
            priv_pem = provided_private_key_pem
        else:
            user = UserRepository.get_by_id(user_id)
            priv_pem = user["private_key_pem"]

        # 3. Time ML-KEM Decapsulation
        kem_alg = key_pkg["kem_algorithm"]
        kem_ciphertext = b64_decode(key_pkg["kem_ciphertext_b64"])

        t_decap_start = time.perf_counter()
        shared_secret = PostQuantumKEM.decapsulate(
            private_key_pem=priv_pem,
            ciphertext=kem_ciphertext,
            algorithm=kem_alg,
        )
        t_decap_end = time.perf_counter()
        decap_time_ms = (t_decap_end - t_decap_start) * 1000.0

        # 4. Derive KEK and unwrap AES file key
        kek = SymmetricCrypto.derive_kek(shared_secret)
        wrap_nonce = b64_decode(key_pkg["wrap_nonce_b64"])
        wrapped_key = b64_decode(key_pkg["wrapped_file_key_b64"])
        file_key = SymmetricCrypto.unwrap_file_key(wrapped_key, wrap_nonce, kek)

        # 5. Read encrypted file from database blob or disk
        ciphertext_payload = file_info.get("encrypted_blob")
        if not ciphertext_payload and file_info.get("stored_path"):
            stored_path = Path(file_info["stored_path"])
            if stored_path.exists():
                try:
                    with open(stored_path, "rb") as f:
                        ciphertext_payload = f.read()
                except Exception:
                    pass

        if not ciphertext_payload:
            raise FileNotFoundError("Encrypted file payload missing from storage.")

        file_nonce = b64_decode(file_info["file_nonce_b64"])
        associated_data = f"file_id:{file_id};filename:{file_info['original_filename']}".encode("utf-8")

        t_decrypt_start = time.perf_counter()
        plaintext = SymmetricCrypto.decrypt_file_data(
            nonce=file_nonce,
            ciphertext_with_tag=ciphertext_payload,
            file_key=file_key,
            associated_data=associated_data,
        )
        t_decrypt_end = time.perf_counter()
        file_decrypt_time_ms = (t_decrypt_end - t_decrypt_start) * 1000.0

        # 6. Verify SHA-256 integrity
        calculated_sha256 = sha256_bytes(plaintext)
        original_sha256 = file_info["sha256_checksum"]
        verified = calculated_sha256 == original_sha256

        t_total_ms = (time.perf_counter() - t_start) * 1000.0

        return {
            "verified": verified,
            "status": "SUCCESS" if verified else "CHECKSUM_MISMATCH",
            "file_id": file_id,
            "filename": file_info["original_filename"],
            "file_size": len(plaintext),
            "calculated_sha256": calculated_sha256,
            "original_sha256": original_sha256,
            "decapsulation_time_ms": round(decap_time_ms, 3),
            "file_decryption_time_ms": round(file_decrypt_time_ms, 3),
            "total_time_ms": round(t_total_ms, 3),
            "file_data_b64": b64_encode(plaintext),
            "message": "File successfully decrypted and SHA-256 verified." if verified else "Integrity check failed!",
        }

    @staticmethod
    def seed_demo_files_if_needed():
        """Seed a representative file shared between Alice, Bob, Charlie, and Dave."""
        alice = UserRepository.get_by_username("alice")
        bob = UserRepository.get_by_username("bob")
        charlie = UserRepository.get_by_username("charlie")
        dave = UserRepository.get_by_username("dave")

        if not (alice and bob and charlie and dave):
            return

        # Check if Alice already has files
        alice_files = FileRepository.list_by_owner(alice["id"])
        if alice_files:
            return

        # Create demo confidential file
        content = (
            "=====================================================================\n"
            "CONFIDENTIAL: PROJECT TITAN - POST-QUANTUM MIGRATION BLUEPRINT\n"
            "Classification: RESTRICTED // INTERNAL RESEARCH ONLY\n"
            "=====================================================================\n\n"
            "1. EXECUTIVE SUMMARY\n"
            "This document establishes the cryptographic migration timeline for transitioning\n"
            "enterprise storage systems from legacy RSA-2048 / ECDH to NIST FIPS 203 ML-KEM.\n\n"
            "2. SECURITY SPECIFICATION\n"
            "- Hybrid Envelope Encryption: AES-256-GCM (data encapsulation) + ML-KEM-768 (key encapsulation)\n"
            "- Multi-Agent Governance: Sender Agent, Policy Agent, and Coordinator Agent\n"
            "- Revocation Policy: Zero trust forward revocation guarantees key encapsulation lockout\n\n"
            "3. INTEGRITY & VERIFICATION\n"
            "The document contents are cryptographically bound via SHA-256 and authenticated with GCM tags.\n"
            "=====================================================================\n"
        ).encode("utf-8")

        file_record = FileService.upload_and_encrypt(
            owner_id=alice["id"],
            filename="Project_Titan_Quantum_Security_Report.txt",
            file_bytes=content,
            mime_type="text/plain",
        )
        file_id = file_record["id"]

        # Share with Bob (Allowed / Active)
        FileService.share_file(
            owner_id=alice["id"],
            file_id=file_id,
            recipient_usernames=["bob"],
            expires_in_hours=72.0,
        )

        # Share with Charlie (then Revoke Charlie)
        FileService.share_file(
            owner_id=alice["id"],
            file_id=file_id,
            recipient_usernames=["charlie"],
            expires_in_hours=24.0,
        )
        FileService.revoke_recipient_access(
            owner_id=alice["id"],
            file_id=file_id,
            recipient_username="charlie",
        )

        # Share with Dave (with expired timestamp)
        FileService.share_file(
            owner_id=alice["id"],
            file_id=file_id,
            recipient_usernames=["dave"],
            expires_in_hours=1.0,
        )
        # Manually backdate Dave's policy to 2 days ago for testing
        yesterday_iso = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        PolicyRepository.set_policy(file_id, dave["id"], status="ALLOWED", expires_at=yesterday_iso)
