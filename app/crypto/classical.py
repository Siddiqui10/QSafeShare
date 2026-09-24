"""Classical asymmetric cryptography implementations for benchmarking vs ML-KEM.

Implements:
- RSA-2048 & RSA-3072 with OAEP (SHA-256)
- ECDH with SECP256R1 (NIST P-256)
- X25519 Key Exchange
"""

import os
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ClassicalCrypto:
    """Classical public-key cryptosystems for research baseline comparisons."""

    # 1. RSA
    @classmethod
    def generate_rsa_keypair(cls, key_size: int = 2048) -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey, int, int]:
        """Generate RSA keypair and return (public_key, private_key, pub_bytes_len, priv_bytes_len)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return public_key, private_key, len(pub_bytes), len(priv_bytes)

    @classmethod
    def rsa_encrypt_key(cls, public_key: rsa.RSAPublicKey, symmetric_key: bytes) -> bytes:
        """Encrypt symmetric key with RSA-OAEP SHA-256."""
        return public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @classmethod
    def rsa_decrypt_key(cls, private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        """Decrypt symmetric key with RSA-OAEP SHA-256."""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # 2. ECDH (NIST P-256)
    @classmethod
    def generate_ecdh_keypair(cls) -> Tuple[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey, int, int]:
        """Generate NIST P-256 ECDH keypair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return public_key, private_key, len(pub_bytes), len(priv_bytes)

    @classmethod
    def ecdh_encapsulate(cls, peer_public_key: ec.EllipticCurvePublicKey) -> Tuple[bytes, bytes]:
        """Simulate KEM with ephemeral ECDH keypair.

        Returns: (derived_shared_secret, ephemeral_public_key_bytes).
        """
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()
        shared_key = ephemeral_priv.exchange(ec.ECDH(), peer_public_key)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecdh-shared-secret",
        ).derive(shared_key)
        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return derived, ephemeral_pub_bytes

    @classmethod
    def ecdh_decapsulate(
        cls, private_key: ec.EllipticCurvePrivateKey, ephemeral_pub_bytes: bytes
    ) -> bytes:
        """Decapsulate shared secret using recipient private key and ephemeral pubkey."""
        ephemeral_pub = serialization.load_der_public_key(ephemeral_pub_bytes)
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecdh-shared-secret",
        ).derive(shared_key)
        return derived
