"""Database Initialization and Connection Management for QSafeShare.

Supports:
1. PostgreSQL (via DATABASE_URL or POSTGRES_URL - recommended for Vercel persistent storage)
2. SQLite (local development and offline runtime)
"""

import os
import ssl
import shutil
import sqlite3
import hashlib
import hmac
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

from app.config import (
    DATABASE_PATH,
    BASE_DIR,
    IS_VERCEL,
    DATABASE_URL,
    USE_POSTGRES,
)

logger = logging.getLogger("qsafeshare.db")


class DictRow(dict):
    """Row object that supports both dictionary access and index access."""
    def __init__(self, cols: List[str], vals: Tuple[Any, ...]):
        super().__init__(zip(cols, vals))
        self._vals = list(vals)

    def __getitem__(self, key: Union[str, int]) -> Any:
        if isinstance(key, int):
            return self._vals[key]
        return super().__getitem__(key)


class PostgresCursorWrapper:
    """Cursor wrapper for pg8000 that mimics sqlite3 Cursor behaviors."""
    def __init__(self, pg_cursor):
        self._cursor = pg_cursor
        self.lastrowid: Optional[int] = None
        self._description = None

    @property
    def description(self):
        return self._cursor.description or self._description

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def execute(self, query: str, params: Optional[Union[Tuple, List]] = None):
        # Translate SQLite datetime('now') syntax to PostgreSQL
        clean_query = query.replace("datetime('now')", "TO_CHAR(CURRENT_TIMESTAMP, 'YYYY-MM-DD\"T\"HH24:MI:SS')")

        # Convert ? placeholders to %s
        clean_query = clean_query.replace("?", "%s")

        # Handle RETURNING id for lastrowid emulation on INSERTs
        needs_returning = (
            clean_query.strip().upper().startswith("INSERT INTO")
            and "RETURNING" not in clean_query.upper()
            and any(t in clean_query.lower() for t in ["users", "agent_audit_logs", "file_policies", "key_packages"])
        )
        if needs_returning:
            clean_query = clean_query.rstrip(" ;") + " RETURNING id"

        clean_params = []
        if params is not None:
            import pg8000.dbapi
            for p in params:
                if isinstance(p, bytes):
                    clean_params.append(pg8000.dbapi.Binary(p))
                else:
                    clean_params.append(p)

        self._cursor.execute(clean_query, clean_params)
        self._description = self._cursor.description

        if needs_returning and self._description:
            try:
                row = self._cursor.fetchone()
                if row:
                    self.lastrowid = row[0]
            except Exception:
                pass

        return self

    def executescript(self, script: str):
        statements = [s.strip() for s in script.split(";") if s.strip()]
        for stmt in statements:
            self.execute(stmt)
        return self

    def fetchone(self) -> Optional[DictRow]:
        row = self._cursor.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self.description]
        return DictRow(cols, row)

    def fetchall(self) -> List[DictRow]:
        rows = self._cursor.fetchall()
        if not rows or not self.description:
            return []
        cols = [d[0] for d in self.description]
        return [DictRow(cols, r) for r in rows]

    def close(self):
        self._cursor.close()


class PostgresConnectionWrapper:
    """Connection wrapper for pg8000."""
    def __init__(self, pg_conn):
        self._conn = pg_conn

    def cursor(self):
        return PostgresCursorWrapper(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def execute(self, query: str, params: Optional[Union[Tuple, List]] = None):
        c = self.cursor()
        c.execute(query, params)
        return c


def _get_postgres_connection():
    import pg8000.dbapi
    p = urllib.parse.urlparse(DATABASE_URL)
    user = urllib.parse.unquote(p.username or "postgres")
    password = urllib.parse.unquote(p.password or "")
    host = p.hostname or "localhost"
    port = p.port or 5432
    database = p.path.lstrip("/") or "postgres"

    # Cloud databases (Neon, Supabase, Vercel Postgres) require SSL
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    raw_conn = pg8000.dbapi.connect(
        user=user,
        password=password,
        host=host,
        port=port,
        database=database,
        ssl_context=ssl_context,
        timeout=15,
    )
    return PostgresConnectionWrapper(raw_conn)


def get_db_connection():
    """Return a database connection (PostgreSQL if DATABASE_URL is configured, else SQLite)."""
    if USE_POSTGRES:
        try:
            return _get_postgres_connection()
        except Exception as e:
            logger.error(f"PostgreSQL connection failed ({e}), falling back to SQLite.")

    # SQLite connection
    if IS_VERCEL and not DATABASE_PATH.exists():
        DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        seed_db = BASE_DIR / "data" / "qsafeshare.db"
        if seed_db.exists():
            shutil.copy2(seed_db, DATABASE_PATH)

    conn = sqlite3.connect(DATABASE_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Create database tables, indices, and run schema migrations for active engine."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if USE_POSTGRES and isinstance(conn, PostgresConnectionWrapper):
        # PostgreSQL Schema
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(150) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            full_name VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user',
            kem_algorithm VARCHAR(50) NOT NULL DEFAULT 'ML-KEM-768',
            public_key_pem TEXT NOT NULL,
            private_key_pem TEXT NOT NULL,
            auth_provider VARCHAR(50) DEFAULT 'local',
            oauth_id VARCHAR(255),
            created_at VARCHAR(100) NOT NULL
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id VARCHAR(100) PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            original_filename VARCHAR(255) NOT NULL,
            stored_path TEXT NOT NULL,
            file_size BIGINT NOT NULL,
            mime_type VARCHAR(150) NOT NULL,
            sha256_checksum VARCHAR(100) NOT NULL,
            encryption_algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
            file_nonce_b64 TEXT NOT NULL,
            encrypted_blob BYTEA,
            created_at VARCHAR(100) NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_policies (
            id SERIAL PRIMARY KEY,
            file_id VARCHAR(100) NOT NULL,
            user_id INTEGER NOT NULL,
            status VARCHAR(50) NOT NULL,
            granted_at VARCHAR(100) NOT NULL,
            expires_at VARCHAR(100),
            revoked_at VARCHAR(100),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(file_id, user_id)
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS key_packages (
            id SERIAL PRIMARY KEY,
            file_id VARCHAR(100) NOT NULL,
            recipient_id INTEGER NOT NULL,
            kem_algorithm VARCHAR(50) NOT NULL,
            kem_ciphertext_b64 TEXT NOT NULL,
            wrap_nonce_b64 TEXT NOT NULL,
            wrapped_file_key_b64 TEXT NOT NULL,
            created_at VARCHAR(100) NOT NULL,
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(file_id, recipient_id)
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_audit_logs (
            id SERIAL PRIMARY KEY,
            timestamp VARCHAR(100) NOT NULL,
            agent_name VARCHAR(100) NOT NULL,
            action VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL,
            user_id INTEGER,
            username VARCHAR(150),
            file_id VARCHAR(100),
            file_name VARCHAR(255),
            details TEXT NOT NULL
        );
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS share_links (
            id VARCHAR(100) PRIMARY KEY,
            file_id VARCHAR(100) NOT NULL,
            creator_id INTEGER,
            protection_mode VARCHAR(50) NOT NULL,
            kem_algorithm VARCHAR(50) DEFAULT 'ML-KEM-768',
            kem_ciphertext_b64 TEXT,
            wrap_nonce_b64 TEXT NOT NULL,
            wrapped_file_key_b64 TEXT NOT NULL,
            secret_key_salt VARCHAR(100),
            status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
            max_downloads INTEGER,
            download_count INTEGER NOT NULL DEFAULT 0,
            created_at VARCHAR(100) NOT NULL,
            expires_at VARCHAR(100),
            revoked_at VARCHAR(100),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
        );
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policies_file ON file_policies(file_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policies_user ON file_policies(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_keys_file_recipient ON key_packages(file_id, recipient_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON agent_audit_logs(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_links_file ON share_links(file_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_links_status ON share_links(status);")

    else:
        # SQLite Schema
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
            status TEXT NOT NULL,
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
            id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            creator_id INTEGER,
            protection_mode TEXT NOT NULL,
            kem_algorithm TEXT DEFAULT 'ML-KEM-768',
            kem_ciphertext_b64 TEXT,
            wrap_nonce_b64 TEXT NOT NULL,
            wrapped_file_key_b64 TEXT NOT NULL,
            secret_key_salt TEXT,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            max_downloads INTEGER,
            download_count INTEGER NOT NULL DEFAULT 0,
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

        # Non-destructive migrations for existing SQLite databases
        migration_statements = [
            "ALTER TABLE files ADD COLUMN encrypted_blob BLOB;",
            "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local';",
            "ALTER TABLE users ADD COLUMN oauth_id TEXT;",
        ]
        for stmt in migration_statements:
            try:
                cursor.execute(stmt)
            except sqlite3.OperationalError:
                pass

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
            salt = "qsafeshare-pwd-salt-2026"
            legacy_hash = hashlib.sha256((salt + plain_password).encode("utf-8")).hexdigest()
            return hmac.compare_digest(legacy_hash, hashed_password)
    except Exception:
        return False
