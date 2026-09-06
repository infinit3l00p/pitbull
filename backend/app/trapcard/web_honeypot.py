"""TrapCard Web Upload Honeypot — FastAPI router accepting file uploads at fake endpoints.

Accepts file uploads at /upload, /api/upload, /admin/upload and other common paths.
Saves uploaded files to capture directory, logs attacker metadata, and returns
fake success responses to keep attackers engaged.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.responses import JSONResponse

from app.trapcard.capture import capture_file

logger = logging.getLogger(__name__)

router = APIRouter(tags=["trapcard-web"])

# ── Fake upload endpoints ─────────────────────────────────────────

UPLOAD_PATHS = [
    "/upload",
    "/api/upload",
    "/admin/upload",
    "/api/v1/upload",
    "/api/files",
    "/admin/api/upload",
    "/wp-admin/upload.php",
    "/api/v1/files",
    "/files/upload",
    "/api/media/upload",
]


@router.post("/upload")
@router.post("/api/upload")
@router.post("/admin/upload")
@router.post("/api/v1/upload")
@router.post("/api/files")
@router.post("/admin/api/upload")
@router.post("/wp-admin/upload.php")
@router.post("/api/v1/files")
@router.post("/files/upload")
@router.post("/api/media/upload")
async def handle_upload(
    request: Request,
    file: UploadFile | None = File(None),
) -> JSONResponse:
    """Accept file uploads and capture them.

    Returns fake success responses to keep attackers engaged.
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    endpoint = request.url.path
    session_id = str(uuid.uuid4())

    # Try to get file from multipart upload
    file_data: bytes = b""
    filename: str | None = None

    if file and file.filename:
        # Standard multipart file upload
        file_data = await file.read()
        filename = file.filename
        content_type = file.content_type or "application/octet-stream"
    else:
        # Try raw body (non-multipart uploads)
        body = await request.body()
        if body:
            file_data = body
            # Try to guess filename from headers or query params
            filename = request.query_params.get("filename") or request.headers.get("X-File-Name") or "raw_upload"
            content_type = request.headers.get("content-type", "application/octet-stream")

    if not file_data:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "No file provided"},
        )

    # Capture the file
    metadata = capture_file(
        file_data=file_data,
        source_ip=client_ip,
        service="web",
        session_id=session_id,
        filename=filename,
    )

    logger.info(
        "TrapCard Web: captured upload from %s at %s — %s (%d bytes, sha256=%s)",
        client_ip, endpoint, filename or "unknown", len(file_data), metadata["sha256"][:16],
    )

    # Log request metadata
    request_meta = {
        "client_ip": client_ip,
        "user_agent": user_agent,
        "endpoint": endpoint,
        "method": request.method,
        "content_type": content_type,
        "content_length": len(file_data),
        "query_params": dict(request.query_params),
        "headers": {
            "accept": request.headers.get("accept"),
            "accept-encoding": request.headers.get("accept-encoding"),
            "accept-language": request.headers.get("accept-language"),
            "referer": request.headers.get("referer"),
            "x-forwarded-for": request.headers.get("x-forwarded-for"),
            "x-real-ip": request.headers.get("x-real-ip"),
        },
        "session_id": session_id,
        "capture_id": metadata["capture_id"],
        "sha256": metadata["sha256"],
        "filename": filename,
        "timestamp": metadata["timestamp"],
    }

    # Store request metadata in Neo4j
    try:
        from app.core.database import cypher_write
        cypher_write(
            """
            MERGE (s:AttackerSession {session_id: $session_id})
            SET s.source_ip = $source_ip,
                s.service = 'web',
                s.user_agent = $user_agent,
                s.endpoint = $endpoint,
                s.first_seen = $timestamp,
                s.last_seen = $timestamp
            """,
            {
                "session_id": session_id,
                "source_ip": client_ip,
                "user_agent": user_agent,
                "endpoint": endpoint,
                "timestamp": metadata["timestamp"],
            },
        )
    except Exception as e:
        logger.debug("TrapCard Web: Neo4j store error: %s", e)

    # Return fake success response
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "File uploaded successfully",
            "file_id": metadata["capture_id"],
            "size": len(file_data),
            "filename": filename,
        },
    )


# ── Fake admin/login endpoints to attract attackers ───────────────

@router.post("/admin/login")
@router.post("/api/login")
@router.post("/api/v1/login")
async def fake_login(request: Request) -> JSONResponse:
    """Fake login endpoint that captures credentials."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    try:
        body = await request.json()
    except Exception:
        body = {}

    username = body.get("username", body.get("email", "unknown"))
    password = body.get("password", "")

    logger.info(
        "TrapCard Web: fake login attempt from %s — username='%s'",
        client_ip, username,
    )

    # Store credential capture
    session_id = str(uuid.uuid4())
    try:
        from app.core.database import cypher_write
        cypher_write(
            """
            MERGE (s:AttackerSession {session_id: $session_id})
            SET s.source_ip = $source_ip,
                s.service = 'web',
                s.username = $username,
                s.first_seen = $timestamp,
                s.last_seen = $timestamp
            """,
            {
                "session_id": session_id,
                "source_ip": client_ip,
                "username": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    except Exception:
        pass

    return JSONResponse(
        status_code=200,
        content={
            "success": False,
            "message": "Invalid credentials",
            "token": None,
        },
    )


# ── Status endpoint for the web honeypot ─────────────────────────

@router.get("/status")
async def web_status() -> dict[str, Any]:
    """Get web honeypot status."""
    return {
        "running": True,  # The router is always available when mounted
        "endpoints": UPLOAD_PATHS,
        "message": "Web upload honeypot active",
    }