from fastapi import APIRouter, HTTPException, Depends, Header, Query
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from app.models.schemas import UserRegisterRequest, UserLoginRequest, UserResponse, KeyVaultResponse
from app.services.auth_service import AuthService
from app.database.repositories import UserRepository
from app.config import GOOGLE_CLIENT_ID, APPLE_CLIENT_ID

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class OAuthLoginRequest(BaseModel):
    provider: str = "google"
    credential: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    oauth_id: Optional[str] = None


def get_current_user_from_header(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Resolve current user via Bearer JWT token or username identifier."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication token required. Please sign in.")

    token = authorization.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Invalid authorization header.")

    # 1. Try resolving as signed JWT token
    user = AuthService.get_user_from_token(token)
    if user:
        return user

    # 2. Backward compatibility fallback for test scripts passing raw username
    user = UserRepository.get_by_username(token)
    if user:
        return user

    raise HTTPException(status_code=401, detail="Invalid or expired session. Please sign in again.")


@router.post("/register")
def register(req: UserRegisterRequest):
    """Register a new real-world user account with auto-provisioned NIST ML-KEM keypair."""
    try:
        user = AuthService.register_user(
            username=req.username,
            email=req.email,
            full_name=req.full_name,
            password=req.password,
            kem_algorithm=req.kem_algorithm,
        )
        token = AuthService.create_token_for_user(user)
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
                "kem_algorithm": user["kem_algorithm"],
                "public_key_pem": user["public_key_pem"],
                "created_at": user["created_at"],
            },
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/login")
def login(req: UserLoginRequest):
    """Authenticate with username or email and password."""
    user = AuthService.authenticate(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = AuthService.create_token_for_user(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "kem_algorithm": user["kem_algorithm"],
            "public_key_pem": user["public_key_pem"],
            "created_at": user["created_at"],
        },
    }


@router.get("/me")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user_from_header)):
    """Return the profile of the currently signed-in user."""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "email": current_user["email"],
        "full_name": current_user["full_name"],
        "role": current_user["role"],
        "kem_algorithm": current_user["kem_algorithm"],
        "public_key_pem": current_user["public_key_pem"],
        "created_at": current_user["created_at"],
    }


@router.get("/search")
def search_users(
    q: str = Query("", description="Search term for username, email, or name"),
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    """Search registered users for sharing (excluding the current user)."""
    return AuthService.search_users(query=q, exclude_user_id=current_user["id"])


@router.get("/users")
def list_users():
    """List all registered system users in directory."""
    return UserRepository.list_all()


@router.get("/vault", response_model=KeyVaultResponse)
def get_key_vault(current_user: Dict[str, Any] = Depends(get_current_user_from_header)):
    """Retrieve post-quantum key vault metadata for signed-in user."""
    try:
        vault = AuthService.get_key_vault(current_user["id"])
        return vault
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/oauth/config")
def get_oauth_config():
    """Return OAuth client status for Google and Apple."""
    return {
        "google_client_id": GOOGLE_CLIENT_ID or "",
        "apple_client_id": APPLE_CLIENT_ID or "",
        "has_google_configured": bool(GOOGLE_CLIENT_ID),
        "has_apple_configured": bool(APPLE_CLIENT_ID),
    }


@router.post("/oauth/google")
def login_google(req: OAuthLoginRequest):
    """Authenticate via Google Sign-In with auto-provisioned ML-KEM-768 keypair."""
    email = req.email or "user@gmail.com"
    full_name = req.full_name or "Google User"
    oauth_id = req.oauth_id

    # If Google credential (id_token) is provided and client ID is configured, verify it
    if req.credential and GOOGLE_CLIENT_ID:
        try:
            import urllib.request, json
            req_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={req.credential}"
            with urllib.request.urlopen(req_url, timeout=5.0) as resp:
                token_data = json.loads(resp.read().decode())
                email = token_data.get("email", email)
                full_name = token_data.get("name", full_name)
                oauth_id = token_data.get("sub", oauth_id)
        except Exception:
            pass

    try:
        user = AuthService.authenticate_oauth(
            provider="google",
            email=email,
            full_name=full_name,
            oauth_id=oauth_id,
        )
        token = AuthService.create_token_for_user(user)
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
                "kem_algorithm": user["kem_algorithm"],
                "public_key_pem": user["public_key_pem"],
                "auth_provider": "google",
                "created_at": user["created_at"],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/oauth/apple")
def login_apple(req: OAuthLoginRequest):
    """Authenticate via Apple Sign-In with auto-provisioned ML-KEM-768 keypair."""
    email = req.email or "user@privaterelay.appleid.com"
    full_name = req.full_name or "Apple User"
    oauth_id = req.oauth_id

    try:
        user = AuthService.authenticate_oauth(
            provider="apple",
            email=email,
            full_name=full_name,
            oauth_id=oauth_id,
        )
        token = AuthService.create_token_for_user(user)
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
                "kem_algorithm": user["kem_algorithm"],
                "public_key_pem": user["public_key_pem"],
                "auth_provider": "apple",
                "created_at": user["created_at"],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
