"""File management, sharing, revocation, and decryption API routes."""

import io
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Query, Header
from fastapi.responses import StreamingResponse
from app.models.schemas import (
    FileUploadResponse,
    ShareFileRequest,
    RevokeAccessRequest,
    ReinstateAccessRequest,
    DecryptVerifyRequest,
    DecryptVerifyResponse,
)
from app.api.auth_routes import get_current_user_from_header
from app.services.file_service import FileService
from app.database.repositories import FileRepository, PolicyRepository
from app.crypto.utils import b64_decode

router = APIRouter(prefix="/api/files", tags=["Files"])


@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        file_rec = FileService.upload_and_encrypt(
            owner_id=current_user["id"],
            filename=file.filename or "unnamed_file.bin",
            file_bytes=content,
            mime_type=file.content_type or "application/octet-stream",
        )

        return {
            "file_id": file_rec["id"],
            "filename": file_rec["original_filename"],
            "file_size": file_rec["file_size"],
            "sha256_checksum": file_rec["sha256_checksum"],
            "encryption_algorithm": file_rec["encryption_algorithm"],
            "created_at": file_rec["created_at"],
            "message": "File successfully encrypted with AES-256-GCM and stored.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/owned")
def get_owned_files(current_user: Dict[str, Any] = Depends(get_current_user_from_header)):
    return FileRepository.list_by_owner(current_user["id"])


@router.get("/shared-with-me")
def get_shared_files(current_user: Dict[str, Any] = Depends(get_current_user_from_header)):
    return FileRepository.list_shared_with_user(current_user["id"])


@router.get("/{file_id}/policies")
def get_file_policies(
    file_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    file_info = FileRepository.get_by_id(file_id)
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    if file_info["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Only the file owner can view policy access rules")

    return PolicyRepository.list_file_policies(file_id)


@router.post("/share")
def share_file(
    req: ShareFileRequest,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    try:
        results = FileService.share_file(
            owner_id=current_user["id"],
            file_id=req.file_id,
            recipient_usernames=req.recipient_usernames,
            expires_in_hours=req.expires_in_hours,
        )
        return {"status": "SUCCESS", "results": results}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/revoke")
def revoke_access(
    req: RevokeAccessRequest,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    try:
        success = FileService.revoke_recipient_access(
            owner_id=current_user["id"],
            file_id=req.file_id,
            recipient_username=req.recipient_username,
        )
        return {
            "status": "SUCCESS" if success else "FAILED",
            "message": f"Access revoked for {req.recipient_username}.",
        }
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/reinstate")
def reinstate_access(
    req: ReinstateAccessRequest,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    try:
        success = FileService.reinstate_recipient_access(
            owner_id=current_user["id"],
            file_id=req.file_id,
            recipient_username=req.recipient_username,
            expires_in_hours=req.expires_in_hours,
        )
        return {
            "status": "SUCCESS" if success else "FAILED",
            "message": f"Access reinstated for {req.recipient_username}.",
        }
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{file_id}/package")
def get_key_package(
    file_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    response = FileService.request_file_package(file_id, current_user["id"])
    if not response["authorized"]:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "ACCESS_DENIED",
                "status": response["status"],
                "message": response["message"],
            },
        )
    return response


@router.post("/{file_id}/decrypt-verify", response_model=DecryptVerifyResponse)
def decrypt_and_verify(
    file_id: str,
    req: DecryptVerifyRequest,
    current_user: Dict[str, Any] = Depends(get_current_user_from_header),
):
    result = FileService.decrypt_and_verify(
        file_id=file_id,
        user_id=current_user["id"],
        provided_private_key_pem=req.private_key_pem,
    )
    if not result.get("verified"):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "ACCESS_DENIED_OR_FAILED",
                "status": result.get("status", "DENIED"),
                "message": result.get("message", "Unable to decrypt file."),
            },
        )
    return result


@router.get("/{file_id}/download-decrypted")
def download_decrypted(
    file_id: str,
    token: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
):
    auth_val = authorization or (f"Bearer {token}" if token else None)
    current_user = get_current_user_from_header(auth_val)

    result = FileService.decrypt_and_verify(file_id=file_id, user_id=current_user["id"])
    if not result.get("verified"):
        raise HTTPException(
            status_code=403,
            detail=result.get("message", "Access denied or decryption failed."),
        )

    raw_bytes = b64_decode(result["file_data_b64"])
    filename = result["filename"]
    file_info = FileRepository.get_by_id(file_id)
    mime_type = file_info["mime_type"] if file_info and file_info.get("mime_type") else "application/octet-stream"

    return StreamingResponse(
        io.BytesIO(raw_bytes),
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
