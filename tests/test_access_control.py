"""Access Control and Policy Matrix tests."""

from datetime import datetime, timezone, timedelta
from app.database import init_db
from app.services.auth_service import AuthService
from app.services.file_service import FileService
from app.database.repositories import UserRepository, FileRepository, PolicyRepository
from app.agents import policy_agent_instance


def setup_module():
    init_db()
    AuthService.seed_demo_users_if_needed()


def test_complete_access_policy_matrix():
    """Verify matrix: Active -> ALLOWED, Revoked -> REVOKED, Expired -> EXPIRED, Unknown -> NO_POLICY."""
    alice = UserRepository.get_by_username("alice")
    bob = UserRepository.get_by_username("bob")
    charlie = UserRepository.get_by_username("charlie")
    dave = UserRepository.get_by_username("dave")
    eve = UserRepository.get_by_username("eve")

    # Ingest a fresh file
    rec = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="policy_matrix_test.txt",
        file_bytes=b"Access matrix test content",
    )
    file_id = rec["id"]

    # 1. Share with Bob (Active / No Expiry)
    FileService.share_file(alice["id"], file_id, ["bob"], expires_in_hours=None)

    # 2. Share with Charlie, then Revoke
    FileService.share_file(alice["id"], file_id, ["charlie"], expires_in_hours=None)
    FileService.revoke_recipient_access(alice["id"], file_id, "charlie")

    # 3. Share with Dave, with expired timestamp (yesterday)
    FileService.share_file(alice["id"], file_id, ["dave"], expires_in_hours=1)
    past_iso = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    PolicyRepository.set_policy(file_id, dave["id"], status="ALLOWED", expires_at=past_iso)

    # 4. Eve is never added to the policy

    # Evaluations
    res_bob = policy_agent_instance.evaluate_access(file_id, bob["id"])
    assert res_bob["is_authorized"] is True
    assert res_bob["status"] == "ALLOWED"

    res_charlie = policy_agent_instance.evaluate_access(file_id, charlie["id"])
    assert res_charlie["is_authorized"] is False
    assert res_charlie["status"] == "REVOKED"

    res_dave = policy_agent_instance.evaluate_access(file_id, dave["id"])
    assert res_dave["is_authorized"] is False
    assert res_dave["status"] == "EXPIRED"

    res_eve = policy_agent_instance.evaluate_access(file_id, eve["id"])
    assert res_eve["is_authorized"] is False
    assert res_eve["status"] == "NO_POLICY"


def test_reinstatement_restores_authorization():
    """Verify revoking and reinstating a recipient toggles access accurately."""
    alice = UserRepository.get_by_username("alice")
    bob = UserRepository.get_by_username("bob")

    rec = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="toggle_test.txt",
        file_bytes=b"Toggle test content",
    )
    file_id = rec["id"]
    FileService.share_file(alice["id"], file_id, ["bob"])

    # Revoke
    FileService.revoke_recipient_access(alice["id"], file_id, "bob")
    assert policy_agent_instance.evaluate_access(file_id, bob["id"])["is_authorized"] is False

    # Reinstate
    FileService.reinstate_recipient_access(alice["id"], file_id, "bob", expires_in_hours=48)
    assert policy_agent_instance.evaluate_access(file_id, bob["id"])["is_authorized"] is True
