"""PITBULL API — Sentinel attack detection endpoints.

Provides real-time attack monitoring, IP blocking, whitelisting, and SSE event streaming.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from starlette.responses import StreamingResponse

from app.core.sentinel.sentinel_engine import SentinelEngine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sentinel"])
# Public router for SSE feed (EventSource can't send API key headers)
public_router = APIRouter(tags=["sentinel"])

# Singleton engine instance
_engine: SentinelEngine | None = None


def _get_engine() -> SentinelEngine:
    """Get or create the SentinelEngine singleton."""
    global _engine
    if _engine is None:
        _engine = SentinelEngine()
    return _engine


# ── Status ────────────────────────────────────────────────────────

@router.get("/sentinel/status")
async def sentinel_status() -> dict[str, Any]:
    """Get Sentinel engine status, threat level, and stats."""
    engine = _get_engine()
    stats = engine.get_stats()
    return {
        "status": "running" if stats["running"] else "stopped",
        "threat_level": stats["threat_level"],
        "stats": stats,
    }


# ── Attack events ─────────────────────────────────────────────────

@router.get("/sentinel/attacks")
async def sentinel_attacks(limit: int = 50) -> dict[str, Any]:
    """Get recent attack events."""
    engine = _get_engine()
    attacks = engine.get_recent_attacks(limit=limit)
    return {
        "count": len(attacks),
        "attacks": attacks,
    }


# ── Attackers ─────────────────────────────────────────────────────

@router.get("/sentinel/attackers")
async def sentinel_attackers() -> dict[str, Any]:
    """Get known attacker profiles."""
    engine = _get_engine()
    attackers = engine.get_attackers()
    return {
        "count": len(attackers),
        "attackers": attackers,
    }


# ── Blocked IPs ────────────────────────────────────────────────────

@router.get("/sentinel/blocked")
async def sentinel_blocked() -> dict[str, Any]:
    """Get list of currently blocked IPs."""
    engine = _get_engine()
    blocked = engine.get_blocked_ips()
    return {
        "count": len(blocked),
        "blocked": blocked,
    }


# ── Manual block / unblock ────────────────────────────────────────

@router.post("/sentinel/block")
async def sentinel_block(ip: str, reason: str = "manual") -> dict[str, Any]:
    """Manually block an IP address."""
    engine = _get_engine()
    return await engine.block_ip(ip, reason=reason)


@router.post("/sentinel/unblock")
async def sentinel_unblock(ip: str, reason: str = "manual") -> dict[str, Any]:
    """Unblock an IP address."""
    engine = _get_engine()
    return await engine.unblock_ip(ip, reason=reason)


# ── Whitelist ─────────────────────────────────────────────────────

@router.get("/sentinel/whitelist")
async def sentinel_whitelist() -> dict[str, Any]:
    """Get whitelisted IPs/CIDRs."""
    engine = _get_engine()
    return {
        "count": len(engine.get_whitelist()),
        "whitelist": engine.get_whitelist(),
    }


@router.post("/sentinel/whitelist/add")
async def sentinel_whitelist_add(ip: str) -> dict[str, Any]:
    """Add an IP or CIDR to the whitelist."""
    engine = _get_engine()
    success = engine.add_whitelist(ip)
    return {"success": success, "ip": ip}


@router.post("/sentinel/whitelist/remove")
async def sentinel_whitelist_remove(ip: str) -> dict[str, Any]:
    """Remove an IP or CIDR from the whitelist."""
    engine = _get_engine()
    success = engine.remove_whitelist(ip)
    return {"success": success, "ip": ip}


# ── SSE Event Stream ─────────────────────────────────────────────

@public_router.get("/sentinel/feed")
async def sentinel_feed() -> StreamingResponse:
    """Server-Sent Events stream of real-time Sentinel events.

    Streams events as JSON objects, one per line, prefixed with ``data:``.
    Event types: ``event`` (raw log), ``attack`` (detection), ``block``, ``unblock``.
    """
    engine = _get_engine()
    queue = engine.subscribe()

    async def event_generator():
        try:
            # Send initial connection confirmation
            yield f"data: {json.dumps({'type': 'connected', 'message': 'Sentinel SSE feed connected'})}\n\n"

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
            engine.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

# ── ntopng Webhook Endpoint ────────────────────────────────────────
@public_router.post("/sentinel/ntopng-webhook")
async def ntopng_webhook(request: Request):
    """Receive ntopng alert webhooks and feed them into Sentinel.

    ntopng sends POST with JSON body containing alert data.
    This endpoint parses it and feeds to the Sentinel engine.
    """
    import logging
    logger = logging.getLogger(__name__)
    try:
        body = await request.json()
    except Exception:
        body = {}

    engine = _get_engine()
    if not engine or not engine._running:
        return {"status": "ok", "message": "Sentinel not running — alert stored"}

    # Parse ntopng webhook format
    alerts = body.get("alerts", [])
    if not isinstance(alerts, list):
        alerts = [body] if body else []

    processed = 0
    for alert in alerts:
        alert_type = "ntopng_alert"
        severity = alert.get("severity", "MEDIUM")
        src_ip = alert.get("src_ip", alert.get("source_ip", "0.0.0.0"))
        dst_ip = alert.get("dst_ip", alert.get("dest_ip", "0.0.0.0"))
        description = alert.get("description", alert.get("message", alert.get("alert", {}).get("message", "Unknown ntopng alert")))
        signature = alert.get("signature", alert.get("alert", {}).get("signature", ""))

        event = {
            "source": "ntopng",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "attack_type": alert_type,
            "severity": severity,
            "details": {
                "alert_type": alert_type,
                "severity": severity,
                "description": description,
                "signature": signature,
                "raw": alert,
            },
        }

        # Feed to Sentinel engine
        try:
            engine._on_vigil_alert(event)
            processed += 1
        except Exception as e:
            logger.warning(f"ntopng webhook: failed to process alert: {e}")

    logger.info(f"ntopng webhook: received {len(alerts)} alerts, processed {processed}")
    return {"status": "ok", "received": len(alerts), "processed": processed}
