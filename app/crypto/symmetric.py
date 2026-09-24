"""Symmetric encryption module for QSafeShare.

Implements:
- AES-256-GCM file encryption and decryption.
- HKDF-SHA256 key derivation from ML-KEM shared secret.
- AES-256-GCM key wrapping (protecting the file AES key for each recipient).
"""

import os
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


class SymmetricCrypto:
    """Handles symmetric cryptographic primitives (AES-256-GCM and HKDF)."""

    KEY_SIZE_BYTES = 32  # 256-bit AES
    NONCE_SIZE_BYTES = 12  # Standard 96-bit GCM nonce
    TAG_SIZE_BYTES = 16    # Standard 128-bit authentication tag

    HKDF_WRAP_INFO = b"QSafeShare-FileKeyWrap-v1"
    WRAP_ASSOCIATED_DATA = b"QSafeShare-KeyPackage-v1"

    @classmethod
    def generate_file_key(cls) -> bytes:
        """Generate a cryptographically secure random 256-bit AES key."""
        return AESGCM.generate_key(bit_length=256)

    @classmethod
    def encrypt_file_data(
        cls,
        file_bytes: bytes,
        file_key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Encrypt file plaintext using AES-256-GCM.

        Args:
            file_bytes: Raw file content.
            file_key: 32-byte AES key.
            associated_data: Optional authenticated data (e.g. file metadata).

        Returns:
            Tuple of (nonce_12_bytes, encrypted_payload_with_tag).
        """
        if len(file_key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"File key must be {cls.KEY_SIZE_BYTES} bytes.")

        nonce = os.urandom(cls.NONCE_SIZE_BYTES)
        aesgcm = AESGCM(file_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, file_bytes, associated_data)
        return nonce, ciphertext_with_tag

    @classmethod
    def decrypt_file_data(
        cls,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        file_key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt file ciphertext using AES-256-GCM.

        Raises:
            InvalidTag: If integrity check fails or key is wrong.
        """
        if len(file_key) != cls.KEY_SIZE_BYTES:
            raise ValueError(f"File key must be {cls.KEY_SIZE_BYTES} bytes.")

        aesgcm = AESGCM(file_key)
        return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)

    @classmethod
    def derive_kek(cls, shared_secret: bytes, salt: Optional[bytes] = None) -> bytes:
        """Derive a 256-bit Key Encryption Key (KEK) from ML-KEM shared secret via HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=cls.KEY_SIZE_BYTES,
            salt=salt,
            info=cls.HKDF_WRAP_INFO,
        )
        return hkdf.derive(shared_secret)

    @classmethod
    def wrap_file_key(cls, file_key: bytes, kek: bytes) -> Tuple[bytes, bytes]:
        """Wrap (encrypt) the file AES key using derived KEK with AES-256-GCM.

        Returns:
            Tuple of (wrap_nonce_12_bytes, wrapped_key_with_tag).
        """
        wrap_nonce = os.urandom(cls.NONCE_SIZE_BYTES)
        aesgcm = AESGCM(kek)
        wrapped_key = aesgcm.encrypt(wrap_nonce, file_key, cls.WRAP_ASSOCIATED_DATA)
        return wrap_nonce, wrapped_key

    @classmethod
    def unwrap_file_key(cls, wrapped_key: bytes, wrap_nonce: bytes, kek: bytes) -> bytes:
        """Unwrap (decrypt) the file AES key using derived KEK with AES-256-GCM.

        Raises:
            InvalidTag: If wrapping MAC verification fails.
        """
        aesgcm = AESGCM(kek)
        return aesgcm.decrypt(wrap_nonce, wrapped_key, cls.WRAP_ASSOCIATED_DATA)
