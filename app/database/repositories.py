"""Data access repositories for SQLite operations with robust connection handling."""

import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from app.database.db import get_db_connection, hash_password


class UserRepository:
    """Repository for user management and public/private key store."""

    @staticmethod
    def create_user(
        username: str,
        email: str,
        full_name: str,
        password_hash: str,
        public_key_pem: str,
        private_key_pem: str,
        role: str = "user",
        kem_algorithm: str = "ML-KEM-768",
        auth_provider: str = "local",
        oauth_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (username, email, full_name, password_hash, role, kem_algorithm, public_key_pem, private_key_pem, auth_provider, oauth_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (username.lower().strip(), email.lower().strip(), full_name, password_hash, role, kem_algorithm, public_key_pem, private_key_pem, auth_provider, oauth_id, now),
            )
            user_id = cursor.lastrowid
            conn.commit()
            return UserRepository.get_by_id(user_id)
        finally:
            conn.close()

    @staticmethod
    def get_by_oauth(provider: str, oauth_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE auth_provider = ? AND oauth_id = ?", (provider, oauth_id))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def get_by_username(username: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username.lower().strip(),))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def get_by_id(user_id: int) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def get_by_email(email: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),))
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def search_users(query: str = "", exclude_user_id: Optional[int] = None, limit: int = 20) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            pattern = f"%{query.lower().strip()}%"
            if exclude_user_id:
                cursor.execute(
                    """
                    SELECT id, username, email, full_name, role, kem_algorithm, public_key_pem, created_at
                    FROM users
                    WHERE id != ? AND (username LIKE ? OR email LIKE ? OR full_name LIKE ?)
                    ORDER BY username ASC LIMIT ?
                    """,
                    (exclude_user_id, pattern, pattern, pattern, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, username, email, full_name, role, kem_algorithm, public_key_pem, created_at
                    FROM users
                    WHERE username LIKE ? OR email LIKE ? OR full_name LIKE ?
                    ORDER BY username ASC LIMIT ?
                    """,
                    (pattern, pattern, pattern, limit),
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def list_all() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, full_name, role, kem_algorithm, public_key_pem, created_at FROM users ORDER BY username ASC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


class FileRepository:
    """Repository for file records."""

    @staticmethod
    def create_file(
        file_id: str,
        owner_id: int,
        original_filename: str,
        stored_path: str,
        file_size: int,
        mime_type: str,
        sha256_checksum: str,
        encryption_algorithm: str,
        file_nonce_b64: str,
        encrypted_blob: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO files (id, owner_id, original_filename, stored_path, file_size, mime_type, sha256_checksum, encryption_algorithm, file_nonce_b64, encrypted_blob, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (file_id, owner_id, original_filename, stored_path, file_size, mime_type, sha256_checksum, encryption_algorithm, file_nonce_b64, encrypted_blob, now),
            )
            conn.commit()
            return FileRepository.get_by_id(file_id)
        finally:
            conn.close()

    @staticmethod
    def get_by_id(file_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT f.*, u.username as owner_username, u.full_name as owner_full_name
                FROM files f
                JOIN users u ON f.owner_id = u.id
                WHERE f.id = ?
                """,
                (file_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def list_by_owner(owner_id: int) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT f.id, f.owner_id, f.original_filename, f.stored_path, f.file_size,
                       f.mime_type, f.sha256_checksum, f.encryption_algorithm, f.file_nonce_b64,
                       f.created_at, u.username as owner_username,
                       (SELECT COUNT(*) FROM file_policies p WHERE p.file_id = f.id) as shared_recipients_count,
                       (SELECT COUNT(*) FROM file_policies p WHERE p.file_id = f.id AND p.status = 'ALLOWED' AND (p.expires_at IS NULL OR p.expires_at > datetime('now'))) as allowed_recipients_count,
                       (SELECT COUNT(*) FROM file_policies p WHERE p.file_id = f.id AND p.status = 'REVOKED') as revoked_recipients_count
                FROM files f
                JOIN users u ON f.owner_id = u.id
                WHERE f.owner_id = ?
                ORDER BY f.created_at DESC
                """,
                (owner_id,),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def list_shared_with_user(user_id: int) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT f.id, f.owner_id, f.original_filename, f.stored_path, f.file_size,
                       f.mime_type, f.sha256_checksum, f.encryption_algorithm, f.file_nonce_b64,
                       f.created_at, u.username as owner_username, u.full_name as owner_full_name,
                       p.status as policy_status, p.granted_at, p.expires_at, p.revoked_at,
                       CASE
                           WHEN p.status = 'REVOKED' THEN 'REVOKED'
                           WHEN p.expires_at IS NOT NULL AND p.expires_at <= datetime('now') THEN 'EXPIRED'
                           ELSE 'ALLOWED'
                       END as effective_status
                FROM file_policies p
                JOIN files f ON p.file_id = f.id
                JOIN users u ON f.owner_id = u.id
                WHERE p.user_id = ?
                ORDER BY p.granted_at DESC
                """,
                (user_id,),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def delete_file(file_id: str) -> bool:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
            affected = cursor.rowcount > 0
            conn.commit()
            return affected
        finally:
            conn.close()


class PolicyRepository:
    """Repository for file access policies (managed by Policy Agent)."""

    @staticmethod
    def set_policy(
        file_id: str,
        user_id: int,
        status: str = "ALLOWED",
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO file_policies (file_id, user_id, status, granted_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                ON CONFLICT(file_id, user_id) DO UPDATE SET
                    status = excluded.status,
                    granted_at = excluded.granted_at,
                    expires_at = excluded.expires_at,
                    revoked_at = NULL
                """,
                (file_id, user_id, status, now, expires_at),
            )
            conn.commit()
            return PolicyRepository.get_policy(file_id, user_id)
        finally:
            conn.close()

    @staticmethod
    def revoke_policy(file_id: str, user_id: int) -> bool:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE file_policies
                SET status = 'REVOKED', revoked_at = ?
                WHERE file_id = ? AND user_id = ?
                """,
                (now, file_id, user_id),
            )
            affected = cursor.rowcount > 0
            conn.commit()
            return affected
        finally:
            conn.close()

    @staticmethod
    def reinstate_policy(file_id: str, user_id: int, expires_at: Optional[str] = None) -> bool:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE file_policies
                SET status = 'ALLOWED', granted_at = ?, expires_at = ?, revoked_at = NULL
                WHERE file_id = ? AND user_id = ?
                """,
                (now, expires_at, file_id, user_id),
            )
            affected = cursor.rowcount > 0
            conn.commit()
            return affected
        finally:
            conn.close()

    @staticmethod
    def get_policy(file_id: str, user_id: int) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT p.*, u.username, u.full_name
                FROM file_policies p
                JOIN users u ON p.user_id = u.id
                WHERE p.file_id = ? AND p.user_id = ?
                """,
                (file_id, user_id),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def list_file_policies(file_id: str) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT p.*, u.username, u.full_name,
                       (SELECT COUNT(*) FROM key_packages k WHERE k.file_id = p.file_id AND k.recipient_id = p.user_id) > 0 as has_key_package,
                       CASE
                           WHEN p.status = 'REVOKED' THEN 'REVOKED'
                           WHEN p.expires_at IS NOT NULL AND p.expires_at <= datetime('now') THEN 'EXPIRED'
                           ELSE 'ALLOWED'
                       END as effective_status
                FROM file_policies p
                JOIN users u ON p.user_id = u.id
                WHERE p.file_id = ?
                ORDER BY u.username ASC
                """,
                (file_id,),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def check_authorization(file_id: str, user_id: int) -> Dict[str, Any]:
        policy = PolicyRepository.get_policy(file_id, user_id)
        if not policy:
            return {"is_authorized": False, "reason": "NO_POLICY", "policy": None}

        if policy["status"] == "REVOKED":
            return {"is_authorized": False, "reason": "REVOKED", "policy": policy}

        if policy.get("expires_at"):
            now_iso = datetime.now(timezone.utc).isoformat()
            if policy["expires_at"] <= now_iso:
                return {"is_authorized": False, "reason": "EXPIRED", "policy": policy}

        return {"is_authorized": True, "reason": "ALLOWED", "policy": policy}


class KeyPackageRepository:
    """Repository for ML-KEM wrapped file key packages."""

    @staticmethod
    def save_key_package(
        file_id: str,
        recipient_id: int,
        kem_algorithm: str,
        kem_ciphertext_b64: str,
        wrap_nonce_b64: str,
        wrapped_file_key_b64: str,
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO key_packages (file_id, recipient_id, kem_algorithm, kem_ciphertext_b64, wrap_nonce_b64, wrapped_file_key_b64, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_id, recipient_id) DO UPDATE SET
                    kem_algorithm = excluded.kem_algorithm,
                    kem_ciphertext_b64 = excluded.kem_ciphertext_b64,
                    wrap_nonce_b64 = excluded.wrap_nonce_b64,
                    wrapped_file_key_b64 = excluded.wrapped_file_key_b64,
                    created_at = excluded.created_at
                """,
                (file_id, recipient_id, kem_algorithm, kem_ciphertext_b64, wrap_nonce_b64, wrapped_file_key_b64, now),
            )
            conn.commit()
            return KeyPackageRepository.get_key_package(file_id, recipient_id)
        finally:
            conn.close()

    @staticmethod
    def get_key_package(file_id: str, recipient_id: int) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT k.*, f.original_filename, f.file_size, f.sha256_checksum, f.file_nonce_b64, f.stored_path
                FROM key_packages k
                JOIN files f ON k.file_id = f.id
                WHERE k.file_id = ? AND k.recipient_id = ?
                """,
                (file_id, recipient_id),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


class AuditRepository:
    """Repository for inter-agent activity and audit trail."""

    @staticmethod
    def log_event(
        agent_name: str,
        action: str,
        status: str,
        details: Any,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        file_id: Optional[str] = None,
        file_name: Optional[str] = None,
    ) -> int:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            details_str = json.dumps(details) if isinstance(details, (dict, list)) else str(details)
            cursor.execute(
                """
                INSERT INTO agent_audit_logs (timestamp, agent_name, action, status, user_id, username, file_id, file_name, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (now, agent_name, action, status, user_id, username, file_id, file_name, details_str),
            )
            log_id = cursor.lastrowid
            conn.commit()
            return log_id
        finally:
            conn.close()

    @staticmethod
    def list_logs(limit: int = 100, agent_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            if agent_filter:
                cursor.execute(
                    """
                    SELECT * FROM agent_audit_logs
                    WHERE agent_name = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (agent_filter, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM agent_audit_logs
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


class LinkRepository:
    """Repository for link-based sharing records."""

    @staticmethod
    def create_link(
        share_token: str,
        file_id: str,
        creator_id: Optional[int],
        protection_mode: str,
        wrap_nonce_b64: str,
        wrapped_file_key_b64: str,
        kem_algorithm: str = "ML-KEM-768",
        kem_ciphertext_b64: Optional[str] = None,
        secret_key_salt: Optional[str] = None,
        expires_at: Optional[str] = None,
        max_downloads: Optional[int] = None,
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO share_links (
                    id, file_id, creator_id, protection_mode, kem_algorithm,
                    kem_ciphertext_b64, wrap_nonce_b64, wrapped_file_key_b64,
                    secret_key_salt, status, max_downloads, download_count,
                    created_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, 0, ?, ?, NULL)
                """,
                (
                    share_token, file_id, creator_id, protection_mode, kem_algorithm,
                    kem_ciphertext_b64, wrap_nonce_b64, wrapped_file_key_b64,
                    secret_key_salt, max_downloads, now, expires_at
                ),
            )
            conn.commit()
            return LinkRepository.get_link(share_token)
        finally:
            conn.close()

    @staticmethod
    def get_link(share_token: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT l.*, f.original_filename, f.file_size, f.mime_type, f.sha256_checksum,
                       f.file_nonce_b64, f.stored_path, f.encrypted_blob, u.username as creator_username, u.full_name as creator_name
                FROM share_links l
                JOIN files f ON l.file_id = f.id
                LEFT JOIN users u ON l.creator_id = u.id
                WHERE l.id = ?
                """,
                (share_token,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def list_by_creator(creator_id: int) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT l.*, f.original_filename, f.file_size,
                       CASE
                           WHEN l.status = 'REVOKED' THEN 'REVOKED'
                           WHEN l.expires_at IS NOT NULL AND l.expires_at <= datetime('now') THEN 'EXPIRED'
                           WHEN l.max_downloads IS NOT NULL AND l.download_count >= l.max_downloads THEN 'LIMIT_REACHED'
                           ELSE 'ACTIVE'
                       END as effective_status
                FROM share_links l
                JOIN files f ON l.file_id = f.id
                WHERE l.creator_id = ?
                ORDER BY l.created_at DESC
                """,
                (creator_id,),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @staticmethod
    def revoke_link(share_token: str) -> bool:
        conn = get_db_connection()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE share_links
                SET status = 'REVOKED', revoked_at = ?
                WHERE id = ?
                """,
                (now, share_token),
            )
            affected = cursor.rowcount > 0
            conn.commit()
            return affected
        finally:
            conn.close()

    @staticmethod
    def increment_download(share_token: str) -> int:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE share_links
                SET download_count = download_count + 1
                WHERE id = ?
                """,
                (share_token,),
            )
            conn.commit()
            cursor.execute("SELECT download_count FROM share_links WHERE id = ?", (share_token,))
            row = cursor.fetchone()
            return row["download_count"] if row else 1
        finally:
            conn.close()

    @staticmethod
    def check_validity(share_token: str) -> Dict[str, Any]:
        link = LinkRepository.get_link(share_token)
        if not link:
            return {"is_valid": False, "status": "NOT_FOUND", "reason": "Link does not exist."}

        if link["status"] == "REVOKED":
            return {"is_valid": False, "status": "REVOKED", "reason": "This secure link has been revoked by the sender."}

        if link.get("expires_at"):
            now_iso = datetime.now(timezone.utc).isoformat()
            if link["expires_at"] <= now_iso:
                return {"is_valid": False, "status": "EXPIRED", "reason": "This secure link has expired."}

        if link.get("max_downloads") and link["download_count"] >= link["max_downloads"]:
            return {"is_valid": False, "status": "LIMIT_REACHED", "reason": "Maximum download limit for this link has been reached."}

        return {"is_valid": True, "status": "ACTIVE", "link": link}
