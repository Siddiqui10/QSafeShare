"""Configuration settings for QSafeShare.

Supports both local runtime and serverless deployment platforms like Vercel.
"""

import os
import tempfile
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"

# Load .env file if present (local development)
_env_path = BASE_DIR / ".env"
if _env_path.exists():
    try:
        with open(_env_path, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip())
    except Exception:
        pass

# Detect Serverless / Vercel deployment
IS_VERCEL = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

# Database Configuration (Supports PostgreSQL for cloud/Vercel and SQLite for local)
DATABASE_URL = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL")
    or os.environ.get("POSTGRES_PRISMA_URL")
    or os.environ.get("POSTGRES_URL_NON_POOLING")
    or ""
).strip()
USE_POSTGRES = bool(DATABASE_URL and ("postgres://" in DATABASE_URL or "postgresql://" in DATABASE_URL))

if IS_VERCEL:
    # Serverless platforms have read-only root filesystems, only /tmp is writable
    DATA_DIR = Path(tempfile.gettempdir()) / "qsafeshare_data"
else:
    data_dir_env = os.environ.get("QSAFESHARE_DATA_DIR")
    DATA_DIR = Path(data_dir_env) if data_dir_env else (BASE_DIR / "data")

UPLOAD_DIR = DATA_DIR / "uploads"
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", str(DATA_DIR / "qsafeshare.db")))

# Ensure data directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Cryptography Settings
# ML-KEM is NIST FIPS 203 standardized Post-Quantum Key Encapsulation Mechanism
DEFAULT_KEM_ALGORITHM = "ML-KEM-768"  # NIST Security Category 3 (approx AES-192)
ALLOWED_KEM_ALGORITHMS = ["ML-KEM-768", "ML-KEM-1024"]

# Symmetric Encryption
SYMMETRIC_ALGORITHM = "AES-256-GCM"
AES_KEY_BYTES = 32  # 256 bits
GCM_NONCE_BYTES = 12  # 96 bits standard nonce
GCM_TAG_BYTES = 16   # 128 bits authentication tag

# Application & Auth Settings
APP_NAME = "QSafeShare"
APP_VERSION = "1.0.0"
SECRET_KEY = os.environ.get("SECRET_KEY", "qsafeshare-post-quantum-secure-session-key-dev")
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

# Demo User Credentials (pre-seeded for easy evaluation)
DEMO_USERS = [
    {"username": "alice", "email": "alice@qsafeshare.io", "full_name": "Alice Smith (Data Owner)", "password": "password123", "role": "sender"},
    {"username": "bob", "email": "bob@qsafeshare.io", "full_name": "Bob Jones (Authorized Recipient)", "password": "password123", "role": "recipient"},
    {"username": "charlie", "email": "charlie@qsafeshare.io", "full_name": "Charlie Brown (Revoked Recipient)", "password": "password123", "role": "recipient"},
    {"username": "dave", "email": "dave@qsafeshare.io", "full_name": "Dave Miller (Expired Access)", "password": "password123", "role": "recipient"},
    {"username": "eve", "email": "eve@qsafeshare.io", "full_name": "Eve Adams (Unauthorized User)", "password": "password123", "role": "recipient"},
]
