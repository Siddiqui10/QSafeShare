"""Link-Based Secure File Sharing Service.

Supports:
- Option 1: Link + Secret Key (Passphrase / Token derived via PBKDF2)
- Option 2: Link + NIST FIPS 203 ML-KEM Keypair (Post-Quantum Key Encapsulation)
"""

import os
import time
import secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple

from app.crypto.pqc_kem import PostQuantumKEM
from app.crypto.symmetric import SymmetricCrypto
from app.crypto.utils import b64_encode, b64_decode, sha256_bytes
from app.database.repositories import LinkRepository, FileRepository, UserRepository
from app.services.file_service import FileService
from app.agents import policy_agent_instance, coordinator_agent_instance, audit_agent_instance
from app.config import DEFAULT_KEM_ALGORITHM


class LinkService:
    """Orchestrates link creation, policy validation, and link-based decryption."""

    @staticmethod
    def _generate_share_token() -> str:
        """Generate a secure, URL-friendly 16-character link token."""
        return secrets.token_urlsafe(12)  # ~16 URL-safe characters

    @staticmethod
    def create_mlkem_link(
        file_id: str,
        creator_id: Optional[int] = None,
        recipient_public_key_pem: Optional[str] = None,
        expires_in_hours: Optional[float] = None,
        max_downloads: Optional[int] = None,
        kem_algorithm: str = DEFAULT_KEM_ALGORITHM,
    ) -> Dict[str, Any]:
        """Create a link protected by NIST ML-KEM (Option 2: Post-Quantum Keypair)."""
        file_info = FileRepository.get_by_id(file_id)
        if not file_info:
            raise ValueError("File not found.")

        # Recover file key (owner unwrap)
        owner_id = file_info["owner_id"]
        file_key = FileService.get_owner_file_key(file_id, owner_id)

        # Handle recipient public key: if none provided, generate keypair for the link!
        recipient_private_key_pem = None
        if not recipient_public_key_pem:
            pub_pem, priv_pem = PostQuantumKEM.generate_keypair(kem_algorithm)
            recipient_public_key_pem = pub_pem
            recipient_private_key_pem = priv_pem

        # 1. Encapsulate post-quantum shared secret against recipient's public key
        shared_secret, kem_ciphertext = PostQuantumKEM.encapsulate(
            recipient_public_key_pem, algorithm=kem_algorithm
        )

        # 2. Derive KEK via HKDF-SHA256 and wrap AES file key
        kek = SymmetricCrypto.derive_kek(shared_secret)
        wrap_nonce, wrapped_file_key = SymmetricCrypto.wrap_file_key(file_key, kek)

        # 3. Calculate expiration
        expires_at = None
        if expires_in_hours and expires_in_hours > 0:
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)).isoformat()

        # 4. Save link record
        share_token = LinkService._generate_share_token()
        link_rec = LinkRepository.create_link(
            share_token=share_token,
            file_id=file_id,
            creator_id=creator_id or owner_id,
            protection_mode="ML_KEM",
            kem_algorithm=kem_algorithm,
            kem_ciphertext_b64=b64_encode(kem_ciphertext),
            wrap_nonce_b64=b64_encode(wrap_nonce),
            wrapped_file_key_b64=b64_encode(wrapped_file_key),
            expires_at=expires_at,
            max_downloads=max_downloads,
        )

        audit_agent_instance.log(
            action="LINK_CREATED_MLKEM",
            status="SUCCESS",
            details={
                "share_token": share_token,
                "file_name": file_info["original_filename"],
                "expires_at": expires_at,
                "max_downloads": max_downloads,
            },
            file_id=file_id,
            file_name=file_info["original_filename"],
        )

        return {
            "share_token": share_token,
            "share_url": f"/share/{share_token}",
            "protection_mode": "ML_KEM",
            "kem_algorithm": kem_algorithm,
            "recipient_public_key_pem": recipient_public_key_pem,
            "recipient_private_key_pem": recipient_private_key_pem,
            "public_key_pem": recipient_public_key_pem,
            "private_key_pem": recipient_private_key_pem,
            "expires_at": expires_at,
            "max_downloads": max_downloads,
            "filename": file_info["original_filename"],
            "file_size": file_info["file_size"],
        }

    @staticmethod
    def create_secret_key_link(
        file_id: str,
        creator_id: Optional[int] = None,
        custom_secret_key: Optional[str] = None,
        expires_in_hours: Optional[float] = None,
        max_downloads: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a link protected by Secret Key / Passphrase (Option 1: Link + Key)."""
        file_info = FileRepository.get_by_id(file_id)
        if not file_info:
            raise ValueError("File not found.")

        owner_id = file_info["owner_id"]
        file_key = FileService.get_owner_file_key(file_id, owner_id)

        # Generate or use custom secret key
        secret_key = custom_secret_key.strip() if custom_secret_key else f"PQC-{secrets.token_hex(8).upper()}"
        salt = os.urandom(16).hex()

        # Derive 256-bit KEK from secret key using PBKDF2-HMAC-SHA256
        import hashlib
        kek = hashlib.pbkdf2_hmac("sha256", secret_key.encode("utf-8"), bytes.fromhex(salt), 100000)

        # Wrap AES file key
        wrap_nonce, wrapped_file_key = SymmetricCrypto.wrap_file_key(file_key, kek)

        expires_at = None
        if expires_in_hours and expires_in_hours > 0:
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)).isoformat()

        share_token = LinkService._generate_share_token()
        link_rec = LinkRepository.create_link(
            share_token=share_token,
            file_id=file_id,
            creator_id=creator_id or owner_id,
            protection_mode="SECRET_KEY",
            wrap_nonce_b64=b64_encode(wrap_nonce),
            wrapped_file_key_b64=b64_encode(wrapped_file_key),
            secret_key_salt=salt,
            expires_at=expires_at,
            max_downloads=max_downloads,
        )

        audit_agent_instance.log(
            action="LINK_CREATED_SECRET_KEY",
            status="SUCCESS",
            details={
                "share_token": share_token,
                "file_name": file_info["original_filename"],
                "expires_at": expires_at,
                "max_downloads": max_downloads,
            },
            file_id=file_id,
            file_name=file_info["original_filename"],
        )

        return {
            "share_token": share_token,
            "share_url": f"/share/{share_token}",
            "protection_mode": "SECRET_KEY",
            "secret_key": secret_key,
            "expires_at": expires_at,
            "max_downloads": max_downloads,
            "filename": file_info["original_filename"],
            "file_size": file_info["file_size"],
        }

    @staticmethod
    def get_link_info(share_token: str) -> Dict[str, Any]:
        """Retrieve public metadata for the recipient landing page (no sensitive keys exposed)."""
        validity = LinkRepository.check_validity(share_token)
        link = LinkRepository.get_link(share_token)
        if not link:
            return {"exists": False, "status": "NOT_FOUND", "message": "Link not found"}

        return {
            "exists": True,
            "is_valid": validity["is_valid"],
            "status": validity["status"],
            "reason": validity.get("reason", ""),
            "share_token": share_token,
            "filename": link["original_filename"],
            "file_size": link["file_size"],
            "mime_type": link["mime_type"],
            "protection_mode": link["protection_mode"],
            "kem_algorithm": link["kem_algorithm"],
            "expires_at": link["expires_at"],
            "created_at": link["created_at"],
            "max_downloads": link["max_downloads"],
            "download_count": link["download_count"],
        }

    @staticmethod
    def decrypt_link_file(share_token: str, credential: str) -> Dict[str, Any]:
        """Validate link validity with PolicyAgent and decrypt using recipient credential."""
        t_start = time.perf_counter()

        # 1. Policy check: Link validity, expiration, and download limits
        validity = LinkRepository.check_validity(share_token)
        if not validity["is_valid"]:
            audit_agent_instance.log(
                action="LINK_ACCESS_REFUSED",
                status="DENIED",
                details={"share_token": share_token, "reason": validity["reason"]},
            )
            return {
                "success": False,
                "status": validity["status"],
                "message": validity["reason"],
            }

        link = validity["link"]
        mode = link["protection_mode"]
        cred = credential.strip()

        # 2. Derive file key depending on protection mode
        t_unwrap_start = time.perf_counter()
        try:
            wrap_nonce = b64_decode(link["wrap_nonce_b64"])
            wrapped_key = b64_decode(link["wrapped_file_key_b64"])

            if mode == "ML_KEM":
                # Credential is the recipient's ML-KEM Private Key (PEM format or raw)
                kem_alg = link["kem_algorithm"] or "ML-KEM-768"
                kem_ct = b64_decode(link["kem_ciphertext_b64"])

                # Post-quantum decapsulation
                shared_secret = PostQuantumKEM.decapsulate(
                    private_key_pem=cred,
                    ciphertext=kem_ct,
                    algorithm=kem_alg,
                )
                kek = SymmetricCrypto.derive_kek(shared_secret)
                file_key = SymmetricCrypto.unwrap_file_key(wrapped_key, wrap_nonce, kek)

            elif mode == "SECRET_KEY":
                # Credential is the shared secret key string
                import hashlib
                salt = link["secret_key_salt"]
                kek = hashlib.pbkdf2_hmac("sha256", cred.encode("utf-8"), bytes.fromhex(salt), 100000)
                file_key = SymmetricCrypto.unwrap_file_key(wrapped_key, wrap_nonce, kek)

            else:
                raise ValueError("Unknown link protection mode.")

            t_unwrap_ms = (time.perf_counter() - t_unwrap_start) * 1000.0

        except Exception as e:
            audit_agent_instance.log(
                action="LINK_DECAPSULATION_FAILED",
                status="DENIED",
                details={"share_token": share_token, "error": "Invalid cryptographic credentials"},
            )
            return {
                "success": False,
                "status": "INVALID_KEY",
                "message": "Invalid cryptographic key or signature mismatch. The file cannot be decrypted.",
            }

        # 3. Read encrypted payload (from database blob or disk storage)
        ciphertext_payload = link.get("encrypted_blob")
        if not ciphertext_payload and link.get("stored_path"):
            stored_path = Path(link["stored_path"])
            if stored_path.exists():
                try:
                    with open(stored_path, "rb") as f:
                        ciphertext_payload = f.read()
                except Exception:
                    pass

        if not ciphertext_payload:
            return {"success": False, "status": "ERROR", "message": "File payload missing from storage."}

        file_nonce = b64_decode(link["file_nonce_b64"])
        associated_data = f"file_id:{link['file_id']};filename:{link['original_filename']}".encode("utf-8")

        t_dec_start = time.perf_counter()
        try:
            plaintext = SymmetricCrypto.decrypt_file_data(
                nonce=file_nonce,
                ciphertext_with_tag=ciphertext_payload,
                file_key=file_key,
                associated_data=associated_data,
            )
            t_dec_ms = (time.perf_counter() - t_dec_start) * 1000.0
        except Exception:
            return {
                "success": False,
                "status": "DECRYPTION_FAILED",
                "message": "Authentication tag verification failed.",
            }

        # 4. SHA-256 Checksum Verification
        calc_sha256 = sha256_bytes(plaintext)
        orig_sha256 = link["sha256_checksum"]
        verified = calc_sha256 == orig_sha256

        # 5. Increment download count
        LinkRepository.increment_download(share_token)

        audit_agent_instance.log(
            action="LINK_FILE_DECRYPTED",
            status="SUCCESS",
            details={
                "share_token": share_token,
                "filename": link["original_filename"],
                "file_size": len(plaintext),
                "protection_mode": mode,
            },
            file_id=link["file_id"],
            file_name=link["original_filename"],
        )

        t_total_ms = (time.perf_counter() - t_start) * 1000.0

        return {
            "success": True,
            "status": "SUCCESS",
            "filename": link["original_filename"],
            "file_size": len(plaintext),
            "mime_type": link["mime_type"],
            "file_bytes": plaintext,
            "calculated_sha256": calc_sha256,
            "original_sha256": orig_sha256,
            "verified": verified,
            "unwrap_time_ms": round(t_unwrap_ms, 3),
            "decrypt_time_ms": round(t_dec_ms, 3),
            "total_time_ms": round(t_total_ms, 3),
            "message": "File successfully decrypted and verified.",
        }

    @staticmethod
    def revoke_link(share_token: str, user_id: Optional[int] = None) -> bool:
        """Revoke a sharing link."""
        link = LinkRepository.get_link(share_token)
        if not link:
            return False

        if user_id and link["creator_id"] and link["creator_id"] != user_id:
            raise PermissionError("Only the creator can revoke this link.")

        revoked = LinkRepository.revoke_link(share_token)
        audit_agent_instance.log(
            action="LINK_REVOKED",
            status="SUCCESS",
            details={"share_token": share_token, "file_name": link["original_filename"]},
            file_id=link["file_id"],
            file_name=link["original_filename"],
        )
        return revoked
