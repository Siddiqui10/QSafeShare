from .auth_routes import router as auth_router
from .file_routes import router as file_router
from .audit_routes import router as audit_router
from .benchmark_routes import router as benchmark_router
from .link_routes import router as link_router

__all__ = [
    "auth_router",
    "file_router",
    "audit_router",
    "benchmark_router",
    "link_router",
]
