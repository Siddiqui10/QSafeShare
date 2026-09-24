"""SQLite Database Initialization and Connection Management for QSafeShare.

Implements industry-standard PBKDF2-HMAC-SHA256 password hashing.
Supports Vercel serverless /tmp seeding and database migrations.
"""

import sqlite3
import hashlib
import os
import shutil
import hmac
from typing import Generator
from app.config import DATABASE_PATH, BASE_DIR, IS_VERCEL


def get_db_connection() -> sqlite3.Connection:
    """Return a configured sqlite3 connection with dict-like row factory."""
    # If in Vercel serverless environment and database does not exist in /tmp, seed it
    if IS_VERCEL and not DATABASE_PATH.exists():
        DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        seed_db = BASE_DIR / "data" / "qsafeshare.db"
        if seed_db.exists():
            shutil.copy2(seed_db, DATABASE_PATH)

    conn = sqlite3.connect(DATABASE_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")  # High concurrency
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Create database tables, indices, and run schema migrations."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        kem_algorithm TEXT NOT NULL DEFAULT 'ML-KEM-768',
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        auth_provider TEXT DEFAULT 'local',
        oauth_id TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        original_filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        sha256_checksum TEXT NOT NULL,
        encryption_algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
        file_nonce_b64 TEXT NOT NULL,
        encrypted_blob BLOB,
        created_at TEXT NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS file_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        status TEXT NOT NULL, -- 'ALLOWED', 'REVOKED'
        granted_at TEXT NOT NULL,
        expires_at TEXT,
        revoked_at TEXT,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(file_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS key_packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id TEXT NOT NULL,
        recipient_id INTEGER NOT NULL,
        kem_algorithm TEXT NOT NULL,
        kem_ciphertext_b64 TEXT NOT NULL,
        wrap_nonce_b64 TEXT NOT NULL,
        wrapped_file_key_b64 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
        FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(file_id, recipient_id)
    );

    CREATE TABLE IF NOT EXISTS agent_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        action TEXT NOT NULL,
        status TEXT NOT NULL,
        user_id INTEGER,
        username TEXT,
        file_id TEXT,
        file_name TEXT,
        details TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS share_links (
        id TEXT PRIMARY KEY,                       -- share token
        file_id TEXT NOT NULL,                     -- foreign key to files(id)
        creator_id INTEGER,                        -- user who created the link
        protection_mode TEXT NOT NULL,             -- 'ML_KEM' or 'SECRET_KEY'
        kem_algorithm TEXT DEFAULT 'ML-KEM-768',   -- NIST algorithm if PQC
        kem_ciphertext_b64 TEXT,                   -- KEM ciphertext (Option 2)
        wrap_nonce_b64 TEXT NOT NULL,              -- AES-GCM nonce for wrapped file key
        wrapped_file_key_b64 TEXT NOT NULL,        -- KEK-wrapped AES file key
        secret_key_salt TEXT,                      -- PBKDF2 salt for Option 1
        status TEXT NOT NULL DEFAULT 'ACTIVE',     -- 'ACTIVE', 'REVOKED', 'EXPIRED'
        max_downloads INTEGER,                     -- Optional download count limit
        download_count INTEGER NOT NULL DEFAULT 0, -- Counter
        created_at TEXT NOT NULL,
        expires_at TEXT,
        revoked_at TEXT,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
        FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
    CREATE INDEX IF NOT EXISTS idx_policies_file ON file_policies(file_id);
    CREATE INDEX IF NOT EXISTS idx_policies_user ON file_policies(user_id);
    CREATE INDEX IF NOT EXISTS idx_keys_file_recipient ON key_packages(file_id, recipient_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON agent_audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_share_links_file ON share_links(file_id);
    CREATE INDEX IF NOT EXISTS idx_share_links_status ON share_links(status);
    """)

    # Non-destructive migrations for existing databases
    migration_statements = [
        "ALTER TABLE files ADD COLUMN encrypted_blob BLOB;",
        "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local';",
        "ALTER TABLE users ADD COLUMN oauth_id TEXT;",
    ]
    for stmt in migration_statements:
        try:
            cursor.execute(stmt)
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """Enterprise-grade PBKDF2-HMAC-SHA256 password hashing (100,000 iterations)."""
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100000).hex()
    return f"pbkdf2:sha256:100000${salt}${dk}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored PBKDF2 hash (supports legacy simple hashes during migration)."""
    try:
        parts = hashed_password.split("$")
        if len(parts) == 3 and parts[0].startswith("pbkdf2"):
            _, salt, expected_dk = parts
            computed_dk = hashlib.pbkdf2_hmac(
                "sha256", plain_password.encode("utf-8"), bytes.fromhex(salt), 100000
            ).hex()
            return hmac.compare_digest(computed_dk, expected_dk)
        else:
            # Fallback legacy verification
            salt = "qsafeshare-pwd-salt-2026"
            legacy_hash = hashlib.sha256((salt + plain_password).encode("utf-8")).hexdigest()
            return hmac.compare_digest(legacy_hash, hashed_password)
    except Exception:
        return False
