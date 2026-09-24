"""Tests for link-based secure file sharing using NIST ML-KEM and Secret Key."""

import os
import io
import pytest
from app.database import init_db
from app.services.auth_service import AuthService
from app.services.file_service import FileService
from app.services.link_service import LinkService
from app.database.repositories import UserRepository


def setup_module():
    init_db()
    AuthService.seed_demo_users_if_needed()


def test_mlkem_link_share_and_decrypt():
    """Test full lifecycle of Option 2: Link + NIST ML-KEM-768 keypair."""
    alice = UserRepository.get_by_username("alice")

    original_payload = b"Confidential Post-Quantum Engineering Specification v2.0"
    file_record = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="specs.pdf",
        file_bytes=original_payload,
        mime_type="application/pdf",
    )

    # 1. Create ML-KEM secure link
    link_info = LinkService.create_mlkem_link(
        file_id=file_record["id"],
        creator_id=alice["id"],
        expires_in_hours=24.0,
        max_downloads=5,
        kem_algorithm="ML-KEM-768",
    )

    assert link_info["share_token"] is not None
    assert link_info["protection_mode"] == "ML_KEM"
    assert "BEGIN PRIVATE KEY" in link_info["private_key_pem"]
    token = link_info["share_token"]
    priv_key = link_info["private_key_pem"]

    # 2. Inspect public link info (landing page)
    public_info = LinkService.get_link_info(token)
    assert public_info["exists"] is True
    assert public_info["filename"] == "specs.pdf"
    assert public_info["protection_mode"] == "ML_KEM"
    assert public_info["status"] == "ACTIVE"

    # 3. Decrypt using the private key
    decrypted_result = LinkService.decrypt_link_file(token, priv_key)
    assert decrypted_result["success"] is True
    assert decrypted_result["verified"] is True
    assert decrypted_result["file_bytes"] == original_payload
    assert decrypted_result["calculated_sha256"] == file_record["sha256_checksum"]

    # 4. Verify download counter incremented
    updated_info = LinkService.get_link_info(token)
    assert updated_info["download_count"] == 1

    # 5. Test invalid key attempt
    invalid_result = LinkService.decrypt_link_file(token, "invalid_pem_key_data")
    assert invalid_result["success"] is False
    assert invalid_result["status"] == "INVALID_KEY"


def test_secret_key_link_share_and_decrypt():
    """Test full lifecycle of Option 1: Link + Secret Key / Passphrase."""
    bob = UserRepository.get_by_username("bob")

    secret_data = b"TOP SECRET: Link-based cryptographic payload without recipient account"
    file_record = FileService.upload_and_encrypt(
        owner_id=bob["id"],
        filename="classified.txt",
        file_bytes=secret_data,
        mime_type="text/plain",
    )

    link_info = LinkService.create_secret_key_link(
        file_id=file_record["id"],
        creator_id=bob["id"],
        custom_secret_key="MySuperSecretPassphrase2026!",
        expires_in_hours=1.0,
    )

    token = link_info["share_token"]
    assert link_info["protection_mode"] == "SECRET_KEY"
    assert link_info["secret_key"] == "MySuperSecretPassphrase2026!"

    # Decrypt with wrong passphrase -> fails
    fail_res = LinkService.decrypt_link_file(token, "WrongPassword!")
    assert fail_res["success"] is False
    assert fail_res["status"] == "INVALID_KEY"

    # Decrypt with correct passphrase -> succeeds
    succ_res = LinkService.decrypt_link_file(token, "MySuperSecretPassphrase2026!")
    assert succ_res["success"] is True
    assert succ_res["file_bytes"] == secret_data


def test_link_revocation():
    """Test immediate real-time revocation of a link by Policy Agent."""
    alice = UserRepository.get_by_username("alice")

    file_record = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="contract.docx",
        file_bytes=b"Standard Corporate Contract 2026",
    )

    link_info = LinkService.create_mlkem_link(
        file_id=file_record["id"],
        creator_id=alice["id"],
    )
    token = link_info["share_token"]
    priv_key = link_info["private_key_pem"]

    # Works before revocation
    res = LinkService.decrypt_link_file(token, priv_key)
    assert res["success"] is True

    # Revoke link
    revoked = LinkService.revoke_link(token, alice["id"])
    assert revoked is True

    # Subsequent access fails immediately with REVOKED
    blocked = LinkService.decrypt_link_file(token, priv_key)
    assert blocked["success"] is False
    assert blocked["status"] == "REVOKED"


def test_download_limit_enforcement():
    """Test burn-after-reading single download limit."""
    alice = UserRepository.get_by_username("alice")

    file_record = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="burner.txt",
        file_bytes=b"Self-destructing data",
    )

    link_info = LinkService.create_secret_key_link(
        file_id=file_record["id"],
        creator_id=alice["id"],
        custom_secret_key="OneTimePass123",
        max_downloads=1,
    )
    token = link_info["share_token"]

    # First download succeeds
    res1 = LinkService.decrypt_link_file(token, "OneTimePass123")
    assert res1["success"] is True

    # Second download rejected due to LIMIT_REACHED
    res2 = LinkService.decrypt_link_file(token, "OneTimePass123")
    assert res2["success"] is False
    assert res2["status"] == "LIMIT_REACHED"
