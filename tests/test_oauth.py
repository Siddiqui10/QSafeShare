"""Tests for Google and Apple Authentication."""

import pytest
from app.database import init_db
from app.services.auth_service import AuthService
from app.database.repositories import UserRepository


def setup_module():
    init_db()
    AuthService.seed_demo_users_if_needed()


def test_google_oauth_authentication():
    """Test Google OAuth sign-in with auto-provisioned ML-KEM keypair."""
    user = AuthService.authenticate_oauth(
        provider="google",
        email="huzaifa.google@example.com",
        full_name="Huzaifa Google",
        oauth_id="google_sub_109283019283",
    )

    assert user is not None
    assert user["email"] == "huzaifa.google@example.com"
    assert user["full_name"] == "Huzaifa Google"
    assert user["auth_provider"] == "google"
    assert user["kem_algorithm"] == "ML-KEM-768"
    assert "BEGIN PUBLIC KEY" in user["public_key_pem"]
    assert "BEGIN PRIVATE KEY" in user["private_key_pem"]

    # Re-authenticating returns the same user without duplicate creation
    same_user = AuthService.authenticate_oauth(
        provider="google",
        email="huzaifa.google@example.com",
        full_name="Huzaifa Google",
        oauth_id="google_sub_109283019283",
    )
    assert same_user["id"] == user["id"]

    # JWT generation works
    token = AuthService.create_token_for_user(user)
    assert token is not None
    resolved = AuthService.get_user_from_token(token)
    assert resolved["id"] == user["id"]


def test_apple_oauth_authentication():
    """Test Apple ID sign-in with auto-provisioned ML-KEM keypair."""
    user = AuthService.authenticate_oauth(
        provider="apple",
        email="huzaifa@privaterelay.appleid.com",
        full_name="Huzaifa Apple",
        oauth_id="apple_sub_981273918237",
    )

    assert user is not None
    assert user["email"] == "huzaifa@privaterelay.appleid.com"
    assert user["auth_provider"] == "apple"
    assert user["kem_algorithm"] == "ML-KEM-768"
    assert "BEGIN PUBLIC KEY" in user["public_key_pem"]

    token = AuthService.create_token_for_user(user)
    assert token is not None


def test_oauth_login_upload_and_list_owned_files():
    """Verify that Google OAuth login followed by upload and /api/files/owned works without 500 error."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    # 1. Login with Google OAuth
    resp = client.post(
        "/api/auth/oauth/google",
        json={
            "provider": "google",
            "email": "huzaifa.test@gmail.com",
            "full_name": "Huzaifa Test",
            "oauth_id": "google_test_12345",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    token = data["access_token"]
    assert token is not None

    headers = {"Authorization": f"Bearer {token}"}

    # 2. Upload and encrypt file
    upload_resp = client.post(
        "/api/files/upload",
        headers=headers,
        files={"file": ("quantum_secret.pdf", b"%PDF-1.4 simulated quantum report content", "application/pdf")},
    )
    assert upload_resp.status_code == 200
    upload_data = upload_resp.json()
    assert upload_data["filename"] == "quantum_secret.pdf"
    assert upload_data["encryption_algorithm"] == "AES-256-GCM"

    # 3. Request /api/files/owned (this previously crashed with HTTP 500 due to encrypted_blob serialization)
    owned_resp = client.get("/api/files/owned", headers=headers)
    assert owned_resp.status_code == 200
    owned_files = owned_resp.json()
    assert isinstance(owned_files, list)
    assert len(owned_files) >= 1
    file_entry = next((f for f in owned_files if f["id"] == upload_data["file_id"]), None)
    assert file_entry is not None
    assert file_entry["original_filename"] == "quantum_secret.pdf"
    assert "encrypted_blob" not in file_entry
