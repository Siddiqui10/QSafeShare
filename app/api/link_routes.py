"""Link-based secure file sharing API routes."""

import io
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends, Query, Form, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.api.auth_routes import get_current_user_from_header
from app.services.link_service import LinkService
from app.database.repositories import LinkRepository
from app.crypto.utils import b64_encode

router = APIRouter(prefix="/api/links", tags=["Link Sharing"])


class CreateMlkemLinkRequest(BaseModel):
    file_id: str
    recipient_public_key_pem: Optional[str] = None
    expires_in_hours: Optional[float] = None
    max_downloads: Optional[int] = None
    kem_algorithm: str = "ML-KEM-768"


class CreateSecretLinkRequest(BaseModel):
    file_id: str
    custom_secret_key: Optional[str] = None
    expires_in_hours: Optional[float] = None
    max_downloads: Optional[int] = None


class DecryptLinkRequest(BaseModel):
    credential: str  # ML-KEM private key PEM or secret key string


@router.post("/create-mlkem")
def create_mlkem_link(
    req: CreateMlkemLinkRequest,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    """Create a post-quantum ML-KEM protected file sharing link (Option 2)."""
    try:
        result = LinkService.create_mlkem_link(
            file_id=req.file_id,
            creator_id=current_user["id"],
            recipient_public_key_pem=req.recipient_public_key_pem,
            expires_in_hours=req.expires_in_hours,
            max_downloads=req.max_downloads,
            kem_algorithm=req.kem_algorithm,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/create-secret")
def create_secret_link(
    req: CreateSecretLinkRequest,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    """Create a Secret Key / Passphrase protected file sharing link (Option 1)."""
    try:
        result = LinkService.create_secret_key_link(
            file_id=req.file_id,
            creator_id=current_user["id"],
            custom_secret_key=req.custom_secret_key,
            expires_in_hours=req.expires_in_hours,
            max_downloads=req.max_downloads,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/my-links")
def get_my_links(current_user: Dict[str, Any] = Depends(get_current_user_from_header)):
    """List all active and revoked links created by the signed-in user."""
    return LinkRepository.list_by_creator(current_user["id"])


@router.get("/{share_token}/info")
def get_link_info(share_token: str):
    """Public endpoint: Inspect file metadata for a shared link (recipient access)."""
    info = LinkService.get_link_info(share_token)
    if not info["exists"]:
        raise HTTPException(status_code=404, detail="Secure sharing link not found.")
    return info


@router.post("/{share_token}/decrypt")
def decrypt_link(share_token: str, req: DecryptLinkRequest):
    """Public endpoint: Decrypt file using recipient cryptographic credential."""
    result = LinkService.decrypt_link_file(share_token=share_token, credential=req.credential)
    if not result["success"]:
        status_code = 403 if result["status"] in ["REVOKED", "EXPIRED", "LIMIT_REACHED", "INVALID_KEY"] else 400
        raise HTTPException(status_code=status_code, detail=result["message"])

    # Convert binary payload to base64 for client display
    return {
        "success": True,
        "filename": result["filename"],
        "file_size": result["file_size"],
        "mime_type": result["mime_type"],
        "calculated_sha256": result["calculated_sha256"],
        "original_sha256": result["original_sha256"],
        "verified": result["verified"],
        "unwrap_time_ms": result["unwrap_time_ms"],
        "decrypt_time_ms": result["decrypt_time_ms"],
        "total_time_ms": result["total_time_ms"],
        "file_data_b64": b64_encode(result["file_bytes"]),
    }


@router.post("/{share_token}/download")
def download_link_file(
    share_token: str,
    credential: str = Form(...),
):
    """Public endpoint: Decrypt and stream recovered binary file directly to browser."""
    result = LinkService.decrypt_link_file(share_token=share_token, credential=credential)
    if not result["success"]:
        raise HTTPException(status_code=403, detail=result["message"])

    filename = result["filename"]
    mime_type = result["mime_type"] or "application/octet-stream"

    return StreamingResponse(
        io.BytesIO(result["file_bytes"]),
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{share_token}/revoke")
def revoke_link(
    share_token: str,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    """Revoke a secure link immediately (enforced by Policy Agent)."""
    try:
        revoked = LinkService.revoke_link(share_token=share_token, user_id=current_user["id"])
        if not revoked:
            raise HTTPException(status_code=404, detail="Link not found or already revoked.")
        return {"status": "SUCCESS", "message": "Link has been revoked."}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
