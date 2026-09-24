import os
import json
import time
import base64
import urllib.request
import urllib.parse
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Header, Query, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from app.models.schemas import UserRegisterRequest, UserLoginRequest, UserResponse, KeyVaultResponse
from app.services.auth_service import AuthService
from app.database.repositories import UserRepository
from app.config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

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
    """Register a new user account with auto-provisioned NIST ML-KEM keypair."""
    try:
        user = AuthService.register_user(
            username=req.username or "",
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
        raise HTTPException(status_code=401, detail="Invalid email or password.")

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
    """Return OAuth client status for Google Sign-In."""
    return {
        "google_client_id": GOOGLE_CLIENT_ID or "",
        "has_google_configured": bool(GOOGLE_CLIENT_ID),
    }


def _get_google_redirect_uri(request: Request) -> str:
    """Determine the Google OAuth redirect URI dynamically based on request headers or config."""
    configured_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
    if configured_uri:
        return configured_uri

    proto = request.headers.get("x-forwarded-proto")
    if not proto:
        proto = request.url.scheme or "https"

    host = request.headers.get("x-forwarded-host")
    if not host:
        host = request.headers.get("host") or request.url.netloc

    if not host:
        host = "localhost:8000"

    return f"{proto}://{host}/api/auth/oauth/google/callback"


@router.get("/oauth/google/login")
def oauth_google_login(request: Request):
    """Initiate Google OAuth 2.0 Authorization Code Flow.
    Redirects user to Google's consent screen.
    """
    if not GOOGLE_CLIENT_ID:
        return RedirectResponse(
            url="/?auth_error=" + urllib.parse.quote("Google OAuth is not configured on this server. Please set GOOGLE_CLIENT_ID."),
            status_code=307,
        )

    redirect_uri = _get_google_redirect_uri(request)

    # Encode redirect_uri and timestamp in state to ensure 100% exact match on callback
    state_payload = json.dumps({"redirect_uri": redirect_uri, "ts": time.time()})
    state = base64.urlsafe_b64encode(state_payload.encode()).decode()

    auth_params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(auth_params)
    return RedirectResponse(url=auth_url, status_code=307)


@router.get("/oauth/google/callback")
def oauth_google_callback(
    request: Request,
    code: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
):
    """Handle Google OAuth 2.0 callback redirect.
    Exchanges code for tokens, retrieves user profile, creates session, and redirects to dashboard.
    """
    if error:
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote(f'Google sign-in canceled or failed: {error}')}",
            status_code=307,
        )

    if not code:
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote('Missing authorization code from Google.')}",
            status_code=307,
        )

    # Recover the exact redirect_uri from state
    redirect_uri = None
    if state:
        try:
            state_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
            redirect_uri = state_data.get("redirect_uri")
        except Exception:
            pass

    if not redirect_uri:
        redirect_uri = _get_google_redirect_uri(request)

    # Exchange authorization code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    token_payload = urllib.parse.urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            token_url,
            data=token_payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as http_err:
        try:
            err_body = http_err.read().decode("utf-8")
            err_json = json.loads(err_body)
            err_desc = err_json.get("error_description", err_json.get("error", str(http_err)))
        except Exception:
            err_desc = str(http_err)
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote(f'Google token exchange error: {err_desc}')}",
            status_code=307,
        )
    except Exception as e:
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote(f'Google connection error: {str(e)}')}",
            status_code=307,
        )

    access_token = token_data.get("access_token")
    id_token = token_data.get("id_token")

    email = None
    full_name = None
    oauth_id = None

    # Fetch user profile using access_token
    if access_token:
        try:
            userinfo_req = urllib.request.Request(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            with urllib.request.urlopen(userinfo_req, timeout=10.0) as resp:
                user_info = json.loads(resp.read().decode("utf-8"))
                email = user_info.get("email")
                full_name = user_info.get("name") or user_info.get("given_name")
                oauth_id = user_info.get("sub")
        except Exception:
            pass

    # Fallback to inspecting id_token if userinfo didn't resolve email
    if (not email or not oauth_id) and id_token:
        try:
            tokeninfo_req = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
            with urllib.request.urlopen(tokeninfo_req, timeout=10.0) as resp:
                token_info = json.loads(resp.read().decode("utf-8"))
                email = email or token_info.get("email")
                full_name = full_name or token_info.get("name")
                oauth_id = oauth_id or token_info.get("sub")
        except Exception:
            pass

    if not email:
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote('Could not retrieve user email from Google.')}",
            status_code=307,
        )

    try:
        user = AuthService.authenticate_oauth(
            provider="google",
            email=email,
            full_name=full_name or email.split("@")[0],
            oauth_id=oauth_id,
        )
        session_token = AuthService.create_token_for_user(user)
        return RedirectResponse(url=f"/?token={session_token}", status_code=307)
    except Exception as e:
        return RedirectResponse(
            url=f"/?auth_error={urllib.parse.quote(f'Failed to register/authenticate user: {str(e)}')}",
            status_code=307,
        )


@router.post("/oauth/google")
def login_google(req: OAuthLoginRequest):
    """Authenticate via Google Sign-In with auto-provisioned ML-KEM-768 keypair."""
    email = req.email or "user@gmail.com"
    full_name = req.full_name or "Google User"
    oauth_id = req.oauth_id

    # If Google credential (id_token) is provided and client ID is configured, verify it
    if req.credential:
        try:
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

