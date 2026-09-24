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


def test_stateless_bundle_inspect_and_decrypt():
    """Test zero-database stateless link bundle survival and decryption."""
    alice = UserRepository.get_by_username("alice")
    payload = b"Stateless Bundle Resilient Payload for Serverless Execution"
    file_record = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="stateless_data.pdf",
        file_bytes=payload,
        mime_type="application/pdf",
    )

    link_info = LinkService.create_secret_key_link(
        file_id=file_record["id"],
        creator_id=alice["id"],
        custom_secret_key="StatelessPass99!",
        expires_in_hours=48.0,
    )

    bundle_b64 = link_info.get("bundle_b64")
    assert bundle_b64 is not None

    # Inspect bundle without credentials
    inspect_res = LinkService.inspect_bundle(bundle_b64)
    assert inspect_res["exists"] is True
    assert inspect_res["is_valid"] is True
    assert inspect_res["filename"] == "stateless_data.pdf"
    assert inspect_res["protection_mode"] == "SECRET_KEY"

    # Decrypt bundle with wrong key
    wrong_res = LinkService.decrypt_bundle_file(bundle_b64, "WrongPassword")
    assert wrong_res["success"] is False
    assert wrong_res["status"] == "INVALID_KEY"

    # Decrypt bundle with correct key
    succ_res = LinkService.decrypt_bundle_file(bundle_b64, "StatelessPass99!")
    assert succ_res["success"] is True
    assert succ_res["file_bytes"] == payload
    assert succ_res["verified"] is True
    assert succ_res["calculated_sha256"] == file_record["sha256_checksum"]


def test_stateless_bundle_expiration():
    """Test that expired stateless bundles are rejected according to chosen expiration."""
    from datetime import datetime, timezone, timedelta
    import gzip, json
    from app.crypto.utils import b64_encode

    # Create a bundle with an expiration time in the past
    past_iso = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    bundle_dict = {
        "v": 1,
        "tok": "expired_test_tok",
        "fid": "fid-123",
        "fn": "old.txt",
        "sz": 10,
        "mt": "text/plain",
        "sha": "dummy",
        "mode": "SECRET_KEY",
        "wn": "dummy",
        "wk": "dummy",
        "s": "dummy",
        "fnn": "dummy",
        "exp": past_iso,
        "max": None,
        "ct": "dummy",
    }
    comp = gzip.compress(json.dumps(bundle_dict).encode("utf-8"))
    bundle_b64 = b64_encode(comp)

    # Inspect should report expired
    insp = LinkService.inspect_bundle(bundle_b64)
    assert insp["is_valid"] is False
    assert insp["status"] == "EXPIRED"

    # Decrypt should reject with EXPIRED
    dec = LinkService.decrypt_bundle_file(bundle_b64, "any_key")
    assert dec["success"] is False
    assert dec["status"] == "EXPIRED"


def test_stateless_api_endpoints_e2e():
    """Test full HTTP API endpoint flow for inspecting and decrypting stateless bundles."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    alice = UserRepository.get_by_username("alice")
    payload = b"Payload for API Endpoint Stateless Bundle Testing"
    file_record = FileService.upload_and_encrypt(
        owner_id=alice["id"],
        filename="api_test.txt",
        file_bytes=payload,
        mime_type="text/plain",
    )

    link_info = LinkService.create_secret_key_link(
        file_id=file_record["id"],
        creator_id=alice["id"],
        custom_secret_key="ApiSecretPass2026!",
        expires_in_hours=72.0,
    )
    bundle_b64 = link_info["bundle_b64"]

    # 1. POST /api/links/inspect-bundle
    resp = client.post("/api/links/inspect-bundle", json={"bundle": bundle_b64})
    assert resp.status_code == 200
    data = resp.json()
    assert data["exists"] is True
    assert data["is_valid"] is True
    assert data["filename"] == "api_test.txt"

    # 2. POST /api/links/decrypt-bundle with wrong password -> 403
    resp_wrong = client.post("/api/links/decrypt-bundle", json={"bundle": bundle_b64, "credential": "bad_password"})
    assert resp_wrong.status_code == 403

    # 3. POST /api/links/decrypt-bundle with correct password -> 200
    resp_succ = client.post("/api/links/decrypt-bundle", json={"bundle": bundle_b64, "credential": "ApiSecretPass2026!"})
    assert resp_succ.status_code == 200
    data_succ = resp_succ.json()
    assert data_succ["success"] is True
    assert data_succ["filename"] == "api_test.txt"
    assert data_succ["verified"] is True
