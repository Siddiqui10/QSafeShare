"""NIST FIPS 203 ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) wrapper.

Supports:
- ML-KEM-768 (NIST Category 3: Security equivalent to AES-192)
- ML-KEM-1024 (NIST Category 5: Security equivalent to AES-256)
"""

import base64
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives import serialization


class PostQuantumKEM:
    """Post-quantum key encapsulation manager using NIST ML-KEM."""

    ALGORITHMS = {
        "ML-KEM-768": {
            "private_cls": mlkem.MLKEM768PrivateKey,
            "public_cls": mlkem.MLKEM768PublicKey,
            "nist_level": 3,
            "public_key_bytes": 1184,
            "ciphertext_bytes": 1088,
            "shared_secret_bytes": 32,
            "quantum_security_claim": "NIST Category 3 (approx. AES-192 equivalent)",
        },
        "ML-KEM-1024": {
            "private_cls": mlkem.MLKEM1024PrivateKey,
            "public_cls": mlkem.MLKEM1024PublicKey,
            "nist_level": 5,
            "public_key_bytes": 1568,
            "ciphertext_bytes": 1568,
            "shared_secret_bytes": 32,
            "quantum_security_claim": "NIST Category 5 (approx. AES-256 equivalent)",
        },
    }

    @classmethod
    def get_algorithm_info(cls, algorithm: str = "ML-KEM-768") -> Dict[str, Any]:
        """Return technical specs of the selected ML-KEM algorithm."""
        if algorithm not in cls.ALGORITHMS:
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Must be one of {list(cls.ALGORITHMS.keys())}")
        info = cls.ALGORITHMS[algorithm].copy()
        # Drop internal python classes from metadata dict
        info.pop("private_cls", None)
        info.pop("public_cls", None)
        return info

    @classmethod
    def generate_keypair(cls, algorithm: str = "ML-KEM-768") -> Tuple[str, str]:
        """Generate ML-KEM public and private keys in PEM format.

        Returns:
            Tuple of (public_key_pem, private_key_pem) strings.
        """
        if algorithm not in cls.ALGORITHMS:
            raise ValueError(f"Unsupported algorithm '{algorithm}'.")

        priv_cls = cls.ALGORITHMS[algorithm]["private_cls"]
        private_key = priv_cls.generate()
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        return public_pem, private_pem

    @classmethod
    def encapsulate(cls, public_key_pem: str, algorithm: str = "ML-KEM-768") -> Tuple[bytes, bytes]:
        """Perform ML-KEM encapsulation using recipient's public key.

        Args:
            public_key_pem: Recipient's ML-KEM public key in PEM format.
            algorithm: 'ML-KEM-768' or 'ML-KEM-1024'.

        Returns:
            Tuple of (shared_secret_32_bytes, kem_ciphertext_bytes).
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        except ValueError as ve:
            raise ValueError(
                "Invalid Post-Quantum Public Key format. The input is not a valid PEM public key block "
                "(it must start with '-----BEGIN PUBLIC KEY-----'). "
                "If you intended to protect the file with a secret password or passphrase, "
                "please select 'Option 1: Secret Key' instead."
            ) from ve

        # Verify instance matches algorithm
        expected_pub_cls = cls.ALGORITHMS[algorithm]["public_cls"]
        if not isinstance(public_key, expected_pub_cls):
            raise TypeError(f"Public key does not match {algorithm} type")

        shared_secret, ciphertext = public_key.encapsulate()
        return shared_secret, ciphertext

    @classmethod
    def decapsulate(cls, private_key_pem: str, ciphertext: bytes, algorithm: str = "ML-KEM-768") -> bytes:
        """Perform ML-KEM decapsulation using recipient's private key.

        Args:
            private_key_pem: Recipient's ML-KEM private key in PEM format.
            ciphertext: ML-KEM ciphertext bytes.
            algorithm: 'ML-KEM-768' or 'ML-KEM-1024'.

        Returns:
            32-byte recovered shared secret.
        """
        try:
            private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        except ValueError as ve:
            raise ValueError(
                "Invalid Post-Quantum Private Key format. The input is not a valid PEM private key "
                "(it must start with '-----BEGIN PRIVATE KEY-----'). "
                "If this file was protected with a passphrase, make sure to enter the correct secret passphrase."
            ) from ve

        expected_priv_cls = cls.ALGORITHMS[algorithm]["private_cls"]
        if not isinstance(private_key, expected_priv_cls):
            raise TypeError(f"Private key does not match {algorithm} type")

        shared_secret = private_key.decapsulate(ciphertext)
        return shared_secret
