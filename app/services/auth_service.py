"""Authentication, session management, and ML-KEM key vault service."""

import os
import json
import time
import hmac
import hashlib
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from app.crypto.pqc_kem import PostQuantumKEM
from app.database.db import hash_password, verify_password
from app.database.repositories import UserRepository
from app.config import DEFAULT_KEM_ALGORITHM, SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES


def create_jwt_token(payload: Dict[str, Any], secret: str = SECRET_KEY, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    """Standard RFC 7519 HMAC-SHA256 JWT Generator."""
    now = time.time()
    payload_copy = payload.copy()
    payload_copy["iat"] = int(now)
    payload_copy["exp"] = int(now + (expires_minutes * 60))

    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload_copy).encode()).decode().rstrip("=")

    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{sig_b64}"


def verify_jwt_token(token: str, secret: str = SECRET_KEY) -> Optional[Dict[str, Any]]:
    """Standard RFC 7519 HMAC-SHA256 JWT Validator."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h_b64, p_b64, sig_b64 = parts

        signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()

        rem_sig = len(sig_b64) % 4
        sig_padded = sig_b64 + ("=" * (4 - rem_sig)) if rem_sig else sig_b64
        actual_sig = base64.urlsafe_b64decode(sig_padded)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        rem_p = len(p_b64) % 4
        p_padded = p_b64 + ("=" * (4 - rem_p)) if rem_p else p_b64
        payload = json.loads(base64.urlsafe_b64decode(p_padded).decode("utf-8"))

        if payload.get("exp") and payload["exp"] < time.time():
            return None  # Token expired

        return payload
    except Exception:
        return None


class AuthService:
    """Production-grade user lifecycle and post-quantum key vault manager."""

    @staticmethod
    def register_user(
        username: str,
        email: str,
        full_name: str,
        password: str,
        kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
        role: str = "user",
    ) -> Dict[str, Any]:
        """Register a new real-world user and provision their native NIST ML-KEM keypair."""
        uname = username.strip().lower()
        umail = email.strip().lower()

        if len(uname) < 3:
            raise ValueError("Username must be at least 3 characters long.")
        if "@" not in umail or "." not in umail:
            raise ValueError("A valid email address is required.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")

        # Check uniqueness
        if UserRepository.get_by_username(uname):
            raise ValueError(f"Username '{uname}' is already registered.")
        if UserRepository.get_by_email(umail):
            raise ValueError(f"Email '{umail}' is already registered.")

        # Generate ML-KEM Keypair (FIPS 203)
        public_pem, private_pem = PostQuantumKEM.generate_keypair(kem_algorithm)
        pwd_hash = hash_password(password)

        user = UserRepository.create_user(
            username=uname,
            email=umail,
            full_name=full_name.strip(),
            password_hash=pwd_hash,
            public_key_pem=public_pem,
            private_key_pem=private_pem,
            role=role,
            kem_algorithm=kem_algorithm,
        )
        return user

    @staticmethod
    def authenticate(username_or_email: str, password: str) -> Optional[Dict[str, Any]]:
        """Validate user credentials against username or email."""
        identifier = username_or_email.strip().lower()
        user = UserRepository.get_by_username(identifier)
        if not user:
            user = UserRepository.get_by_email(identifier)
        if not user:
            return None
        if not verify_password(password, user["password_hash"]):
            return None
        return user

    @staticmethod
    def authenticate_oauth(
        provider: str,
        email: str,
        full_name: str,
        oauth_id: Optional[str] = None,
        kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    ) -> Dict[str, Any]:
        """Authenticate or auto-register user via OAuth provider (Google or Apple)."""
        clean_email = email.strip().lower()
        if not clean_email or "@" not in clean_email:
            raise ValueError("A valid email address is required for OAuth sign-in.")

        clean_provider = provider.strip().lower()

        # 1. Lookup existing user by oauth_id or email
        user = None
        if oauth_id:
            user = UserRepository.get_by_oauth(clean_provider, oauth_id)
        if not user:
            user = UserRepository.get_by_email(clean_email)

        if user:
            return user

        # 2. Derive unique username from email
        prefix = clean_email.split("@")[0].replace(".", "_").replace("+", "_")
        candidate_username = f"{prefix}"
        counter = 1
        while UserRepository.get_by_username(candidate_username):
            candidate_username = f"{prefix}_{counter}"
            counter += 1

        # 3. Generate native NIST ML-KEM post-quantum keypair for new account
        public_pem, private_pem = PostQuantumKEM.generate_keypair(kem_algorithm)
        dummy_hash = f"oauth:{clean_provider}:{oauth_id or clean_email}"

        user = UserRepository.create_user(
            username=candidate_username,
            email=clean_email,
            full_name=full_name.strip() or f"{provider.capitalize()} User",
            password_hash=dummy_hash,
            public_key_pem=public_pem,
            private_key_pem=private_pem,
            role="user",
            kem_algorithm=kem_algorithm,
            auth_provider=clean_provider,
            oauth_id=oauth_id,
        )
        return user

    @staticmethod
    def create_token_for_user(user: Dict[str, Any]) -> str:
        """Create a signed JWT token for the user."""
        return create_jwt_token({
            "sub": user["username"],
            "user_id": user["id"],
            "email": user["email"],
            "role": user["role"],
        })

    @staticmethod
    def get_user_from_token(token: str) -> Optional[Dict[str, Any]]:
        """Resolve database user from a JWT token."""
        payload = verify_jwt_token(token)
        if not payload or "sub" not in payload:
            return None
        return UserRepository.get_by_username(payload["sub"])

    @staticmethod
    def search_users(query: str = "", exclude_user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Search registered users for file sharing."""
        return UserRepository.search_users(query=query, exclude_user_id=exclude_user_id)

    @staticmethod
    def get_key_vault(user_id: int) -> Dict[str, Any]:
        """Retrieve user's post-quantum key vault metadata."""
        user = UserRepository.get_by_id(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found.")

        kem_alg = user.get("kem_algorithm", DEFAULT_KEM_ALGORITHM)
        algo_info = PostQuantumKEM.get_algorithm_info(kem_alg)

        return {
            "user_id": user["id"],
            "username": user["username"],
            "kem_algorithm": kem_alg,
            "public_key_pem": user["public_key_pem"],
            "private_key_pem": user["private_key_pem"],
            "public_key_bytes_len": algo_info["public_key_bytes"],
            "ciphertext_bytes_len": algo_info["ciphertext_bytes"],
            "nist_level": algo_info["nist_level"],
            "security_claim": algo_info["quantum_security_claim"],
        }

    @staticmethod
    def seed_demo_users_if_needed():
        """Ensure test benchmark users exist if needed for automated test suites."""
        from app.config import DEMO_USERS
        for demo in DEMO_USERS:
            existing = UserRepository.get_by_username(demo["username"])
            if not existing:
                try:
                    AuthService.register_user(
                        username=demo["username"],
                        email=demo["email"],
                        full_name=demo["full_name"],
                        password=demo["password"],
                        kem_algorithm=DEFAULT_KEM_ALGORITHM,
                        role=demo["role"],
                    )
                except ValueError:
                    pass
