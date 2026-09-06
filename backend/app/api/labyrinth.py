"""EPHEMERAL LABYRINTH API endpoints.

Exposes the Labyrinth system through the PITBULL FastAPI backend.
All endpoints are tagged with "labyrinth" and mounted under /labyrinth/ in main.py.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import asyncio
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.labyrinth.controller import get_labyrinth_controller, LabyrinthState
from app.labyrinth.erosion_engine import FakeSuccessType

logger = logging.getLogger(__name__)

router = APIRouter(tags=["labyrinth"])
# Public router for SSE feed (EventSource can't send API key headers)
public_router = APIRouter(tags=["labyrinth"])


# ═══════════════════════════════════════════════════════════════════════
#  REQUEST MODELS
# ═══════════════════════════════════════════════════════════════════════

class ArmRequest(BaseModel):
    scale: float = Field(default=1.0, ge=0.1, le=5.0, description="Mirror size multiplier")


class ConnectionEvent(BaseModel):
    source_ip: str = Field(..., max_length=45)
    dest_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp", max_length=10)


class DnsEvent(BaseModel):
    source_ip: str = Field(..., max_length=45)
    query: str = Field(..., max_length=253)
    query_type: str = Field(default="A", max_length=10)


class HttpEvent(BaseModel):
    source_ip: str = Field(..., max_length=45)
    method: str = Field(..., max_length=10)
    path: str = Field(..., max_length=2048)
    user_agent: str = Field(default="", max_length=512)


class ShellEvent(BaseModel):
    source_ip: str = Field(..., max_length=45)
    command: str = Field(..., max_length=1024)


class AuthEvent(BaseModel):
    source_ip: str = Field(..., max_length=45)
    username: str = Field(..., max_length=128)
    success: bool
    service: str = Field(default="ssh", max_length=20)


class BehaviorEvent(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    behavior_type: str = Field(..., max_length=50)


class InteractionRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    context: Optional[dict[str, Any]] = None


# ═══════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/labyrinth/status")
async def labyrinth_status() -> dict[str, Any]:
    """Get the full status of the EPHEMERAL LABYRINTH system."""
    controller = get_labyrinth_controller()
    return controller.get_status()


@router.post("/labyrinth/arm")
async def labyrinth_arm(req: ArmRequest) -> dict[str, Any]:
    """Arm the Labyrinth: generate MirrorGraph + validate consistency."""
    controller = get_labyrinth_controller()
    if controller.state not in (LabyrinthState.IDLE, LabyrinthState.POST_INCIDENT):
        raise HTTPException(status_code=409, detail=f"System is already {controller.state.value}")
    # FIX (18:25): generate_mirror is heavy SYNC work — running it directly in the
    # async handler BLOCKED the event loop → /health unanswered → pitbull-watchdog
    # declared the backend dead and fuser -k'd it (SIGKILL) mid-generation. Every
    # arm attempt = backend murdered at ~16s (journal: ARMING → KILL → restart → idle).
    # to_thread keeps the loop free: health checks pass, watchdog stays calm, arm completes.
    result = await asyncio.to_thread(controller.arm, req.scale)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return result


@router.post("/labyrinth/disarm")
async def labyrinth_disarm() -> dict[str, Any]:
    """Disarm the Labyrinth: clear MirrorGraph and reset."""
    controller = get_labyrinth_controller()
    if controller.state == LabyrinthState.IDLE:
        raise HTTPException(status_code=409, detail="System is already idle")
    # to_thread — same reason as arm: graph teardown is sync/heavy, keep the loop free
    return await asyncio.to_thread(controller.disarm)


@router.get("/labyrinth/mirror")
async def labyrinth_mirror() -> dict[str, Any]:
    """Get the current MirrorGraph for inspection."""
    controller = get_labyrinth_controller()
    data = controller.get_mirror()
    # Sanitize Neo4j DateTime objects for JSON serialization
    def sanitize(obj):
        if isinstance(obj, dict):
            return {k: sanitize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [sanitize(v) for v in obj]
        elif hasattr(obj, 'iso_format'):  # neo4j.time.DateTime
            return obj.iso_format()
        elif hasattr(obj, 'isoformat'):  # datetime.date
            return obj.isoformat()
        return obj
    return sanitize(data)


@router.get("/labyrinth/validate")
async def labyrinth_validate() -> dict[str, Any]:
    """Re-run consistency validation on the MirrorGraph."""
    controller = get_labyrinth_controller()
    result = controller.validate()
    return {
        "summary": result.summary(),
        "is_valid": result.is_valid,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "warning_count": result.warning_count,
        "violations": [
            {
                "check": v.check,
                "severity": v.severity,
                "node_id": v.node_id,
                "node_type": v.node_type,
                "details": v.details,
                "fix_hint": v.fix_hint,
            }
            for v in result.violations
        ],
    }


# ── Event ingestion ────────────────────────────────────────────────────

@router.post("/labyrinth/connection")
async def labyrinth_connection_event(req: ConnectionEvent) -> dict[str, Any]:
    """Feed a network connection event to the recon detector."""
    controller = get_labyrinth_controller()
    result = controller.process_connection(req.source_ip, req.dest_port, req.protocol)
    return result or {"event": None, "message": "No reconnaissance detected"}


@router.post("/labyrinth/dns")
async def labyrinth_dns_event(req: DnsEvent) -> dict[str, Any]:
    """Feed a DNS query event to the recon detector."""
    controller = get_labyrinth_controller()
    result = controller.process_dns(req.source_ip, req.query, req.query_type)
    return result or {"event": None, "message": "No reconnaissance detected"}


@router.post("/labyrinth/http")
async def labyrinth_http_event(req: HttpEvent) -> dict[str, Any]:
    """Feed an HTTP request event to the recon detector."""
    controller = get_labyrinth_controller()
    result = controller.process_http(req.source_ip, req.method, req.path, req.user_agent)
    return result or {"event": None, "message": "No reconnaissance detected"}


@router.post("/labyrinth/shell")
async def labyrinth_shell_event(req: ShellEvent) -> dict[str, Any]:
    """Feed a shell command event to the recon detector."""
    controller = get_labyrinth_controller()
    result = controller.process_shell(req.source_ip, req.command)
    return result or {"event": None, "message": "No reconnaissance detected"}


@router.post("/labyrinth/auth")
async def labyrinth_auth_event(req: AuthEvent) -> dict[str, Any]:
    """Feed an authentication event to the recon detector."""
    controller = get_labyrinth_controller()
    result = controller.process_auth(req.source_ip, req.username, req.success, req.service)
    return result or {"event": None, "message": "No reconnaissance detected"}


@router.post("/labyrinth/behavior")
async def labyrinth_behavior_event(req: BehaviorEvent) -> dict[str, Any]:
    """Feed a behavioral indicator from the attacker."""
    controller = get_labyrinth_controller()
    result = controller.process_behavior(req.attacker_ip, req.behavior_type)
    return result or {"event": None, "message": "No phase change"}


# ── Attacker interaction ───────────────────────────────────────────────

@router.post("/labyrinth/interact")
async def labyrinth_interact(req: InteractionRequest) -> dict[str, Any]:
    """Serve the next interaction to an attacker.

    The system decides whether to serve a fake success or a dead end
    based on the erosion engine's strategy.
    """
    controller = get_labyrinth_controller()
    return controller.serve_interaction(req.attacker_ip, req.context)


# ── Reporting ───────────────────────────────────────────────────────────

@router.get("/labyrinth/attackers")
async def labyrinth_attackers() -> dict[str, Any]:
    """Get all tracked attackers and their profiles."""
    controller = get_labyrinth_controller()
    return {
        "attackers": controller.get_status()["attackers"],
        "erosion_states": controller.get_status()["erosion_states"],
    }


@router.get("/labyrinth/engagement")
async def labyrinth_engagement_log() -> dict[str, Any]:
    """Get the full engagement log."""
    controller = get_labyrinth_controller()
    return {
        "logs": controller.get_engagement_log(),
        "count": len(controller.get_engagement_log()),
    }


@router.get("/labyrinth/logs")
async def labyrinth_logs(limit: int = 50) -> dict[str, Any]:
    """Get recent system logs (REST polling fallback)."""
    controller = get_labyrinth_controller()
    return {
        "logs": controller.get_recent_logs(limit=limit),
        "count": len(controller.get_recent_logs(limit=limit)),
    }


@public_router.get("/labyrinth/feed")
async def labyrinth_feed():
    """SSE stream of Labyrinth system logs in real-time."""
    controller = get_labyrinth_controller()

    async def event_generator():
        # Send initial connection confirmation
        yield f"data: {json.dumps({'type': 'connected', 'message': 'Labyrinth SSE feed connected'})}\n\n"
        async for entry in controller.subscribe_logs():
            yield f"data: {json.dumps(entry)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )