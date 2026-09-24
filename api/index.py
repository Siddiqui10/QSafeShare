"""Vercel Serverless Function entrypoint for QSafeShare."""

import os
import sys
from pathlib import Path

# Add project root directory to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Set Vercel serverless environment flag
os.environ["VERCEL"] = "1"

from app.main import app
from app.database import init_db
from app.services.auth_service import AuthService
from app.services.file_service import FileService

# Initialize database and demo seeds for serverless execution
try:
    init_db()
    AuthService.seed_demo_users_if_needed()
    FileService.seed_demo_files_if_needed()
except Exception:
    pass

# Expose both app and handler for Vercel runtime compatibility
handler = app
