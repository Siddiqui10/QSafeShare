"""End-to-End File Sharing, Encryption, Decryption, and Revocation Workflow Tests."""

import os
from app.database import init_db
from app.services.auth_service import AuthService
from app.services.file_service import FileService
from app.crypto.utils import sha256_bytes, b64_decode
from app.database.repositories import UserRepository


def setup_module():
    init_db()
    AuthService.seed_demo_users_if_needed()


def test_complete_upload_share_decrypt_revoke_lifecycle():
    """Test full cycle: Alice uploads -> shares with Bob -> Bob decrypts -> Alice revokes -> Bob blocked."""
    alice = UserRepository.get_by_username("alice")
    bob = UserRepository.get_by_username("bob")

    original_content = b"CRITICAL RESEARCH PAYLOAD: Quantum Algorithms for Molecular Simulation."
    original_checksum = sha256_bytes(original_content)

    # 1. Upload & Ingest (Sender Agent)
    file_record = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="molecular_simulation.dat",
        file_bytes=original_content,
        mime_type="application/octet-stream",
    )
    file_id = file_record["id"]
    assert file_record["sha256_checksum"] == original_checksum

    # 2. Share with Bob (Coordinator Agent performs ML-KEM encapsulation)
    share_results = FileService.share_file(
        owner_id=alice["id"],
        file_id=file_id,
        recipient_usernames=["bob"],
        expires_in_hours=24.0,
    )
    assert len(share_results) == 1
    assert share_results[0]["status"] == "SUCCESS"

    # 3. Bob requests key package and decrypts (Decapsulation + AES Decrypt)
    decrypt_result = FileService.decrypt_and_verify(
        file_id=file_id,
        user_id=bob["id"],
    )
    assert decrypt_result["verified"] is True
    assert decrypt_result["status"] == "SUCCESS"
    assert decrypt_result["calculated_sha256"] == original_checksum

    recovered_bytes = b64_decode(decrypt_result["file_data_b64"])
    assert recovered_bytes == original_content

    # 4. Alice revokes Bob's access
    revoke_success = FileService.revoke_recipient_access(
        owner_id=alice["id"],
        file_id=file_id,
        recipient_username="bob",
    )
    assert revoke_success is True

    # 5. Bob tries to decrypt again -> Policy Agent blocks!
    blocked_result = FileService.decrypt_and_verify(
        file_id=file_id,
        user_id=bob["id"],
    )
    assert blocked_result["verified"] is False
    assert blocked_result["status"] == "REVOKED"
