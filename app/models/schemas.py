"""Pydantic data schemas for QSafeShare."""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


# User Schemas
class UserRegisterRequest(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    kem_algorithm: str = "ML-KEM-768"


class UserLoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    kem_algorithm: str
    public_key_pem: str
    created_at: str


class KeyVaultResponse(BaseModel):
    user_id: int
    username: str
    kem_algorithm: str
    public_key_pem: str
    private_key_pem: str
    public_key_bytes_len: int
    security_claim: str


# File Schemas
class FileUploadResponse(BaseModel):
    file_id: str
    filename: str
    file_size: int
    sha256_checksum: str
    encryption_algorithm: str
    created_at: str
    message: str


class FileMetadataResponse(BaseModel):
    id: str
    owner_id: int
    owner_username: str
    original_filename: str
    file_size: int
    mime_type: str
    sha256_checksum: str
    encryption_algorithm: str
    created_at: str
    shared_recipients_count: int
    allowed_recipients_count: int
    revoked_recipients_count: int


# Policy & Access Schemas
class ShareFileRequest(BaseModel):
    file_id: str
    recipient_usernames: List[str]
    expires_in_hours: Optional[float] = None  # None means perpetual until revoked


class AccessPolicyItem(BaseModel):
    user_id: int
    username: str
    full_name: str
    status: str  # "ALLOWED", "REVOKED", "EXPIRED"
    granted_at: str
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    has_key_package: bool


class RevokeAccessRequest(BaseModel):
    file_id: str
    recipient_username: str


class ReinstateAccessRequest(BaseModel):
    file_id: str
    recipient_username: str
    expires_in_hours: Optional[float] = None


class KeyPackageResponse(BaseModel):
    file_id: str
    filename: str
    file_size: int
    original_sha256: str
    kem_algorithm: str
    kem_ciphertext_b64: str
    wrap_nonce_b64: str
    wrapped_file_key_b64: str
    file_nonce_b64: str
    status: str  # "ALLOWED"


class DecryptVerifyRequest(BaseModel):
    file_id: str
    private_key_pem: Optional[str] = None  # If not provided, user's key in session is used


class DecryptVerifyResponse(BaseModel):
    file_id: str
    filename: str
    file_size: int
    verified: bool
    calculated_sha256: str
    original_sha256: str
    decapsulation_time_ms: float
    file_decryption_time_ms: float
    total_time_ms: float
    file_data_b64: Optional[str] = None
    message: str


# Multi-Agent Messaging Schemas
class AgentMessage(BaseModel):
    message_id: str
    sender_agent: str
    target_agent: str
    action: str
    payload: Dict[str, Any]
    timestamp: str


class AuditLogResponse(BaseModel):
    id: int
    timestamp: str
    agent_name: str
    action: str
    status: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    file_id: Optional[str] = None
    file_name: Optional[str] = None
    details: str


# Benchmark Schemas
class BenchmarkRequest(BaseModel):
    iterations: int = 10
    recipient_counts: List[int] = [1, 5, 10, 25, 50]
    payload_sizes_kb: List[int] = [10, 100, 1024, 10240]
