"""Unit tests for the Multi-Agent architecture (Sender, Policy, Coordinator, Audit)."""

import os
from app.database import init_db
from app.services.auth_service import AuthService
from app.agents import (
    sender_agent_instance,
    policy_agent_instance,
    coordinator_agent_instance,
    audit_agent_instance,
)
from app.database.repositories import UserRepository, FileRepository, PolicyRepository


def setup_module():
    init_db()
    AuthService.seed_demo_users_if_needed()


def test_agent_names_and_roles():
    """Verify agent identities and roles."""
    assert sender_agent_instance.name == "SenderAgent"
    assert policy_agent_instance.name == "PolicyAgent"
    assert coordinator_agent_instance.name == "CoordinatorAgent"
    assert audit_agent_instance.name == "AuditAgent"


def test_sender_agent_ingestion_and_encryption():
    """Verify SenderAgent encrypts plaintext and produces file record."""
    alice = UserRepository.get_by_username("alice")
    payload = b"Top secret data for testing SenderAgent."
    file_record, file_key = sender_agent_instance.ingest_and_encrypt(
        owner_id=alice["id"],
        filename="agent_test_file.txt",
        file_bytes=payload,
    )
    assert file_record["owner_id"] == alice["id"]
    assert file_record["encryption_algorithm"] == "AES-256-GCM"
    assert len(file_key) == 32
    assert os.path.exists(file_record["stored_path"])


def test_policy_agent_grant_and_revoke():
    """Verify PolicyAgent handles access mutations."""
    alice = UserRepository.get_by_username("alice")
    bob = UserRepository.get_by_username("bob")

    # Ingest a real file first to satisfy foreign key constraint
    file_record, _ = sender_agent_instance.ingest_and_encrypt(
        owner_id=alice["id"],
        filename="policy_agent_test.txt",
        file_bytes=b"Testing policy agent",
    )
    file_id = file_record["id"]

    # 1. Grant access
    policy = policy_agent_instance.grant_access(file_id, bob["id"], expires_in_hours=10)
    assert policy["status"] == "ALLOWED"

    # 2. Evaluate access -> ALLOWED
    decision = policy_agent_instance.evaluate_access(file_id, bob["id"])
    assert decision["is_authorized"] is True
    assert decision["status"] == "ALLOWED"

    # 3. Revoke access
    revoked = policy_agent_instance.revoke_access(file_id, bob["id"])
    assert revoked is True

    # 4. Evaluate access -> REVOKED
    decision_after = policy_agent_instance.evaluate_access(file_id, bob["id"])
    assert decision_after["is_authorized"] is False
    assert decision_after["status"] == "REVOKED"


def test_coordinator_agent_refuses_revoked_recipient():
    """Verify CoordinatorAgent queries PolicyAgent and refuses key distribution to revoked user."""
    alice = UserRepository.get_by_username("alice")
    bob = UserRepository.get_by_username("bob")

    # Ingest file
    file_record, file_key = sender_agent_instance.ingest_and_encrypt(
        owner_id=alice["id"],
        filename="refusal_test.txt",
        file_bytes=b"Sensitive secret document",
    )
    file_id = file_record["id"]

    # Share with Bob
    coordinator_agent_instance.process_sharing_request(
        file_id=file_id,
        file_key=file_key,
        recipient_users=[bob],
    )

    # Bob should be authorized initially
    resp1 = coordinator_agent_instance.request_key_release(file_id, bob["id"])
    assert resp1["authorized"] is True

    # Now PolicyAgent revokes Bob
    policy_agent_instance.revoke_access(file_id, bob["id"])

    # CoordinatorAgent MUST refuse key distribution
    resp2 = coordinator_agent_instance.request_key_release(file_id, bob["id"])
    assert resp2["authorized"] is False
    assert resp2["status"] == "REVOKED"


def test_audit_agent_captures_events():
    """Verify AuditAgent captures recent audit trail."""
    logs = audit_agent_instance.get_audit_trail(limit=10)
    assert len(logs) > 0
    assert any(l["agent_name"] in ["SenderAgent", "PolicyAgent", "CoordinatorAgent"] for l in logs)
