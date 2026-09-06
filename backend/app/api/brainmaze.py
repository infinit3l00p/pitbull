"""BrainMaze API endpoints.

Exposes the BrainMaze cognitive confusion engine through the PITBULL FastAPI backend.
All endpoints are tagged with "brainmaze" and mounted under /api/v1/brainmaze.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.brainmaze.orchestrator import get_brainmaze_orchestrator
from app.brainmaze.persona import PersonaType, get_persona_engine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["brainmaze"])
# Public router for SSE feed (EventSource can't send API key headers)
public_router = APIRouter(tags=["brainmaze"])


# ═══════════════════════════════════════════════════════════════════════
#  REQUEST MODELS
# ═══════════════════════════════════════════════════════════════════════

class PersonaSelectRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    persona_type: Optional[str] = Field(default=None, description="Persona type to select; auto-select if omitted")


class PersonaRespondRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    attacker_input: str = Field(..., max_length=2048)
    context: Optional[dict[str, Any]] = None


class TrailGenerateRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    trail_type: str = Field(..., description="Type: dns, credentials, history, config, users")
    domain: str = Field(default="corp.local", max_length=253)
    filename: str = Field(default=".env.production", max_length=256)
    count: int = Field(default=10, ge=1, le=50)


class ParanoiaInjectRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    paranoia_type: str = Field(..., description="Type: logs, sessions, network, processes, crontab")


class WasterGenerateRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    waster_type: str = Field(..., description="Type: database, filesystem, api_docs, source_code, git_repo")
    name: str = Field(default="production", max_length=128)
    rows: int = Field(default=1000, ge=10, le=10000)
    depth: int = Field(default=3, ge=1, le=5)
    filename: str = Field(default="app.py", max_length=256)


class CommandProcessRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    command: str = Field(..., max_length=1024)


class TimeElapsedRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)
    seconds: int = Field(..., ge=1, le=86400)


class DeadEndRequest(BaseModel):
    attacker_ip: str = Field(..., max_length=45)


# ═══════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/status")
async def brainmaze_status() -> dict[str, Any]:
    """Get the full BrainMaze status, active personas, and deployed trails."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.get_status()


@router.get("/techniques")
async def brainmaze_techniques() -> list[dict[str, Any]]:
    """List all available confusion techniques."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.get_techniques()


@router.get("/analytics")
async def brainmaze_analytics() -> dict[str, Any]:
    """Get confusion effectiveness statistics."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.get_analytics()


@router.get("/attacker/{ip}/confusion")
async def brainmaze_attacker_confusion(ip: str) -> dict[str, Any]:
    """Get confusion score for a specific attacker."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.get_confusion_status(ip)


@router.get("/attacker/{ip}/history")
async def brainmaze_attacker_history(ip: str) -> dict[str, Any]:
    """Get confusion technique history for a specific attacker."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.get_confusion_history(ip)


# ── Persona Endpoints ───────────────────────────────────────────────────

@router.post("/persona/select")
async def brainmaze_persona_select(req: PersonaSelectRequest) -> dict[str, Any]:
    """Select a persona for an attacker interaction."""
    orchestrator = get_brainmaze_orchestrator()
    result = orchestrator.deploy_persona(req.attacker_ip, req.persona_type)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post("/persona/respond")
async def brainmaze_persona_respond(req: PersonaRespondRequest) -> dict[str, Any]:
    """Generate a persona response to attacker input."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.generate_persona_response(
        req.attacker_ip, req.attacker_input, req.context
    )


@router.get("/persona/interactions")
async def brainmaze_persona_interactions(attacker_ip: Optional[str] = None) -> dict[str, Any]:
    """Get persona interaction history."""
    engine = get_persona_engine()
    history = engine.get_interaction_history(attacker_ip)
    return {"interactions": history, "count": len(history)}


# ── False Trails Endpoints ──────────────────────────────────────────────

@router.post("/trails/generate")
async def brainmaze_trails_generate(req: TrailGenerateRequest) -> dict[str, Any]:
    """Generate false trails for an attacker."""
    orchestrator = get_brainmaze_orchestrator()

    if req.trail_type == "dns":
        # Use the domain from request
        state = orchestrator.get_state(req.attacker_ip)
        state.trails_deployed += 1
        result = orchestrator.trail_generator.generate_fake_dns(req.domain)
        orchestrator._record_technique(state, "false_trail", {"trail_type": "dns", "trail_id": result.get("trail_id")})
        return result
    elif req.trail_type == "credentials":
        return orchestrator.deploy_false_trails(req.attacker_ip, "credentials")
    elif req.trail_type == "history":
        return orchestrator.deploy_false_trails(req.attacker_ip, "history")
    elif req.trail_type == "config":
        state = orchestrator.get_state(req.attacker_ip)
        state.trails_deployed += 1
        result = orchestrator.trail_generator.generate_fake_config(req.filename)
        orchestrator._record_technique(state, "false_trail", {"trail_type": "config", "trail_id": result.get("trail_id")})
        return result
    elif req.trail_type == "users":
        return orchestrator.deploy_false_trails(req.attacker_ip, "users")
    else:
        raise HTTPException(status_code=400, detail=f"Unknown trail type: {req.trail_type}")


# ── Paranoia Endpoints ──────────────────────────────────────────────────

@router.post("/paranoia/inject")
async def brainmaze_paranoia_inject(req: ParanoiaInjectRequest) -> dict[str, Any]:
    """Inject paranoia indicators for an attacker."""
    orchestrator = get_brainmaze_orchestrator()
    result = orchestrator.deploy_paranoia(req.attacker_ip, req.paranoia_type)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ── Time Wasters Endpoints ──────────────────────────────────────────────

@router.post("/wasters/generate")
async def brainmaze_wasters_generate(req: WasterGenerateRequest) -> dict[str, Any]:
    """Generate time wasters for an attacker."""
    orchestrator = get_brainmaze_orchestrator()
    state = orchestrator.get_state(req.attacker_ip)
    state.wasters_deployed += 1

    if req.waster_type == "database":
        result = orchestrator.time_waster_gen.generate_fake_database(req.name, req.rows)
    elif req.waster_type == "filesystem":
        result = orchestrator.time_waster_gen.generate_fake_filesystem(req.depth)
    elif req.waster_type == "api_docs":
        result = orchestrator.time_waster_gen.generate_fake_api_docs()
    elif req.waster_type == "source_code":
        result = orchestrator.time_waster_gen.generate_fake_source_code(req.filename)
    elif req.waster_type == "git_repo":
        result = orchestrator.time_waster_gen.generate_fake_git_repo()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown waster type: {req.waster_type}")

    orchestrator._record_technique(state, "time_waster", {"waster_type": req.waster_type, "waster_id": result.get("waster_id")})
    return result


# ── Behavioral Tracking Endpoints ──────────────────────────────────────

@router.post("/attacker/command")
async def brainmaze_attacker_command(req: CommandProcessRequest) -> dict[str, Any]:
    """Process a command from an attacker and update confusion score."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.process_command(req.attacker_ip, req.command)


@router.post("/attacker/dead-end")
async def brainmaze_attacker_dead_end(req: DeadEndRequest) -> dict[str, Any]:
    """Record that the attacker hit a dead end."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.process_dead_end(req.attacker_ip)


@router.post("/attacker/time-elapsed")
async def brainmaze_attacker_time_elapsed(req: TimeElapsedRequest) -> dict[str, Any]:
    """Record time elapsed for an attacker in the system."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.process_time_elapsed(req.attacker_ip, req.seconds)


# ── Erosion Engine Integration ──────────────────────────────────────────

@router.post("/attacker/{ip}/feed-erosion")
async def brainmaze_feed_erosion(ip: str) -> dict[str, Any]:
    """Feed confusion data into the Labyrinth erosion engine."""
    orchestrator = get_brainmaze_orchestrator()
    return orchestrator.feed_erosion_engine(ip)


# ── SSE Feed ────────────────────────────────────────────────────────────

@public_router.get("/feed")
async def brainmaze_feed():
    """SSE stream of BrainMaze confusion events in real-time."""
    orchestrator = get_brainmaze_orchestrator()

    async def event_generator():
        yield f"data: {json.dumps({'type': 'connected', 'message': 'BrainMaze SSE feed connected', 'source': 'brainmaze'})}\n\n"
        async for entry in orchestrator.subscribe_events():
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