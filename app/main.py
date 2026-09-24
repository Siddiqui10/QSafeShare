"""QSafeShare Application Main Entry Point."""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.config import APP_NAME, APP_VERSION
from app.database import init_db
from app.services.auth_service import AuthService
from app.services.file_service import FileService
from app.api import auth_router, file_router, audit_router, benchmark_router, link_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database and Demo Seed Data
    init_db()
    AuthService.seed_demo_users_if_needed()
    FileService.seed_demo_files_if_needed()
    yield
    # Shutdown logic if needed


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Post-Quantum Secure Multi-Agent File Sharing using NIST ML-KEM and AES-256-GCM",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth_router)
app.include_router(file_router)
app.include_router(audit_router)
app.include_router(benchmark_router)
app.include_router(link_router)

# Mount Static Files
static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
def serve_index():
    """Serve the single page web application."""
    index_path = static_dir / "index.html"
    return FileResponse(str(index_path))


@app.get("/share/{share_token}")
def serve_share_page(share_token: str):
    """Serve the recipient secure decryption landing page."""
    share_page_path = static_dir / "share.html"
    return FileResponse(str(share_page_path))


@app.get("/api/health")
def health_check():
    """Health status and crypto capability check."""
    return {
        "status": "ONLINE",
        "app": APP_NAME,
        "version": APP_VERSION,
        "pqc_standard": "NIST FIPS 203 (ML-KEM)",
        "symmetric_cipher": "AES-256-GCM",
        "agents": ["SenderAgent", "PolicyAgent", "CoordinatorAgent", "AuditAgent"],
    }
