"""Unit tests for cryptographic components (NIST ML-KEM, AES-256-GCM, HKDF)."""

import os
import pytest
from app.crypto.pqc_kem import PostQuantumKEM
from app.crypto.symmetric import SymmetricCrypto
from app.crypto.classical import ClassicalCrypto
from app.crypto.utils import sha256_bytes
from cryptography.exceptions import InvalidTag


def test_mlkem_768_keypair_generation():
    """Verify ML-KEM-768 keypair generation and PEM formatting."""
    pub_pem, priv_pem = PostQuantumKEM.generate_keypair("ML-KEM-768")
    assert "BEGIN PUBLIC KEY" in pub_pem
    assert "BEGIN PRIVATE KEY" in priv_pem


def test_mlkem_1024_keypair_generation():
    """Verify ML-KEM-1024 keypair generation."""
    pub_pem, priv_pem = PostQuantumKEM.generate_keypair("ML-KEM-1024")
    assert "BEGIN PUBLIC KEY" in pub_pem
    assert "BEGIN PRIVATE KEY" in priv_pem


def test_mlkem_768_encapsulate_decapsulate():
    """Verify ML-KEM-768 shared secret agreement."""
    pub_pem, priv_pem = PostQuantumKEM.generate_keypair("ML-KEM-768")
    shared_secret_enc, ciphertext = PostQuantumKEM.encapsulate(pub_pem, "ML-KEM-768")
    assert len(shared_secret_enc) == 32
    assert len(ciphertext) == 1088  # NIST standard ciphertext size

    shared_secret_dec = PostQuantumKEM.decapsulate(priv_pem, ciphertext, "ML-KEM-768")
    assert shared_secret_dec == shared_secret_enc


def test_mlkem_1024_encapsulate_decapsulate():
    """Verify ML-KEM-1024 shared secret agreement."""
    pub_pem, priv_pem = PostQuantumKEM.generate_keypair("ML-KEM-1024")
    shared_secret_enc, ciphertext = PostQuantumKEM.encapsulate(pub_pem, "ML-KEM-1024")
    assert len(shared_secret_enc) == 32
    assert len(ciphertext) == 1568  # NIST standard ciphertext size

    shared_secret_dec = PostQuantumKEM.decapsulate(priv_pem, ciphertext, "ML-KEM-1024")
    assert shared_secret_dec == shared_secret_enc


def test_aes_256_gcm_encryption_decryption():
    """Verify AES-256-GCM authenticated encryption and decryption."""
    data = b"Confidential post-quantum research payload."
    key = SymmetricCrypto.generate_file_key()
    assert len(key) == 32

    nonce, ciphertext = SymmetricCrypto.encrypt_file_data(data, key, associated_data=b"test-ad")
    assert len(nonce) == 12

    recovered = SymmetricCrypto.decrypt_file_data(nonce, ciphertext, key, associated_data=b"test-ad")
    assert recovered == data


def test_aes_gcm_tamper_detection():
    """Verify AES-GCM detects tampering and raises InvalidTag."""
    data = b"Sensitive payload"
    key = SymmetricCrypto.generate_file_key()
    nonce, ciphertext = SymmetricCrypto.encrypt_file_data(data, key)

    # Tamper with ciphertext byte
    tampered = bytearray(ciphertext)
    tampered[5] ^= 0xFF

    with pytest.raises(InvalidTag):
        SymmetricCrypto.decrypt_file_data(nonce, bytes(tampered), key)


def test_key_wrapping_and_unwrapping():
    """Verify KEK derivation and file key wrapping."""
    file_key = SymmetricCrypto.generate_file_key()
    shared_secret = os.urandom(32)

    kek = SymmetricCrypto.derive_kek(shared_secret)
    assert len(kek) == 32

    wrap_nonce, wrapped_key = SymmetricCrypto.wrap_file_key(file_key, kek)
    assert len(wrap_nonce) == 12

    unwrapped_file_key = SymmetricCrypto.unwrap_file_key(wrapped_key, wrap_nonce, kek)
    assert unwrapped_file_key == file_key


def test_classical_crypto_baselines():
    """Verify classical RSA and ECDH operations execute correctly for benchmarks."""
    # RSA
    rsa_pub, rsa_priv, _, _ = ClassicalCrypto.generate_rsa_keypair(2048)
    secret = b"12345678901234567890123456789012"
    rsa_ct = ClassicalCrypto.rsa_encrypt_key(rsa_pub, secret)
    recovered_rsa = ClassicalCrypto.rsa_decrypt_key(rsa_priv, rsa_ct)
    assert recovered_rsa == secret

    # ECDH
    ecdh_pub, ecdh_priv, _, _ = ClassicalCrypto.generate_ecdh_keypair()
    ss, eph_pub = ClassicalCrypto.ecdh_encapsulate(ecdh_pub)
    recovered_ss = ClassicalCrypto.ecdh_decapsulate(ecdh_priv, eph_pub)
    assert recovered_ss == ss
