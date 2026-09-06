"""PITBULL API — TrapCard attacker tool capture endpoints.

Provides honeypot control, capture listing, session recordings, analytics,
and real-time SSE event streaming for TrapCard events.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter
from starlette.responses import StreamingResponse

from app.trapcard.capture import (
    get_analytics,
    get_capture,
    get_session,
    list_captures,
    list_sessions,
)
from app.trapcard.ssh_honeypot import ssh_honeypot

logger = logging.getLogger(__name__)

router = APIRouter(tags=["trapcard"])
# Public router for SSE feed (EventSource can't send API key headers)
public_router = APIRouter(tags=["trapcard"])


# ── Status ────────────────────────────────────────────────────────

@router.get("/status")
async def trapcard_status() -> dict[str, Any]:
    """Get TrapCard honeypot services status, total captures, and recent sessions."""
    ssh_status = ssh_honeypot.get_status()
    analytics = get_analytics()

    return {
        "ssh_honeypot": ssh_status,
        "web_honeypot": {
            "running": True,
            "endpoints": ["/upload", "/api/upload", "/admin/upload"],
        },
        "total_captures": analytics["total_captures"],
        "total_sessions": analytics["total_sessions"],
        "total_attackers": analytics["total_attackers"],
    }


# ── Captures ──────────────────────────────────────────────────────

@router.get("/captures")
async def trapcard_captures(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List all captured tool samples with pagination."""
    return list_captures(limit=limit, offset=offset)


@router.get("/captures/{capture_id}")
async def trapcard_capture_detail(capture_id: str) -> dict[str, Any]:
    """Get specific capture details."""
    capture = get_capture(capture_id)
    if not capture:
        return {"error": "Capture not found", "capture_id": capture_id}
    return capture


# ── Sessions ──────────────────────────────────────────────────────

@router.get("/sessions")
async def trapcard_sessions(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List all attacker sessions."""
    return list_sessions(limit=limit, offset=offset)


@router.get("/sessions/{session_id}")
async def trapcard_session_detail(session_id: str) -> dict[str, Any]:
    """Get session recording and details."""
    session = get_session(session_id)
    if not session:
        return {"error": "Session not found", "session_id": session_id}
    return session


# ── SSH Honeypot Control ───────────────────────────────────────────

@router.post("/ssh/start")
async def trapcard_ssh_start(port: int = 2222, host: str = "0.0.0.0") -> dict[str, Any]:
    """Start the SSH honeypot on the specified port."""
    return await ssh_honeypot.start(port=port, host=host)


@router.post("/ssh/stop")
async def trapcard_ssh_stop() -> dict[str, Any]:
    """Stop the SSH honeypot."""
    return await ssh_honeypot.stop()


# ── Web Honeypot Control ───────────────────────────────────────────
# The web honeypot is a FastAPI router that's always available when mounted.
# These endpoints are for API completeness — the web honeypot starts when
# the TrapCard router is mounted.

@router.post("/web/start")
async def trapcard_web_start() -> dict[str, Any]:
    """Start the web upload honeypot (always available when router is mounted)."""
    return {
        "success": True,
        "message": "Web honeypot is active — endpoints available at /upload, /api/upload, /admin/upload",
        "endpoints": ["/upload", "/api/upload", "/admin/upload", "/api/v1/upload", "/api/files"],
    }


@router.post("/web/stop")
async def trapcard_web_stop() -> dict[str, Any]:
    """Stop the web upload honeypot (would require unmounting the router)."""
    return {
        "success": False,
        "message": "Web honeypot router cannot be stopped at runtime — unmount the router to disable",
    }


# ── Analytics ─────────────────────────────────────────────────────

@router.get("/analytics")
async def trapcard_analytics() -> dict[str, Any]:
    """Get capture analytics: by type, by IP, by day, ATT&CK mapping."""
    return get_analytics()


# ── SSE Event Stream ──────────────────────────────────────────────

@public_router.get("/feed")
async def trapcard_feed() -> StreamingResponse:
    """Server-Sent Events stream of real-time TrapCard events.

    Streams events as JSON objects, one per line, prefixed with ``data:``.
    Event types: ``ssh_connect``, ``ssh_disconnect``, ``ssh_auth``, ``ssh_command``,
    ``file_captured``, ``web_upload``.
    """
    queue = ssh_honeypot.subscribe()

    async def event_generator():
        try:
            # Send initial connection confirmation
            yield f"data: {json.dumps({'type': 'connected', 'message': 'TrapCard SSE feed connected'})}\n\n"

            while True:
                try:
                    # Wait for next event with timeout (for keepalive)
                    data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json.dumps(data, default=str)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield f": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            ssh_honeypot.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )