"""PITBULL API — SSE stream for real-time mission logs."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.api.explore import _missions
from app.api.exploit import _active_streams

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sse"])


@router.get("/mission/{mission_id}")
async def stream_mission(mission_id: str):
    """Server-Sent Events stream for a mission's live logs."""

    async def event_generator():
        sent_logs = 0
        while True:
            if mission_id not in _missions:
                yield {"event": "error", "data": json.dumps({"error": "Mission not found"})}
                break

            mission = _missions[mission_id]
            new_logs = mission["logs"][sent_logs:]

            for log in new_logs:
                yield {
                    "event": "log",
                    "data": json.dumps({
                        "timestamp": datetime.now().isoformat(),
                        "message": log,
                        "mission_id": mission_id,
                    }),
                }
                sent_logs += 1

            # Send status updates
            yield {
                "event": "status",
                "data": json.dumps({
                    "status": mission["status"],
                    "discoveries": mission["discoveries"],
                    "mission_id": mission_id,
                }),
            }

            if mission["status"] in ("completed", "failed"):
                yield {
                    "event": "done",
                    "data": json.dumps({"mission_id": mission_id, "status": mission["status"]}),
                }
                break

            await asyncio.sleep(1.0)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/health-stream")
async def health_stream():
    """SSE stream for health updates (every 5 seconds)."""

    async def event_generator():
        from app.core.database import test_connection
        while True:
            data = {
                "status": "healthy" if test_connection() else "degraded",
                "neo4j_connected": test_connection(),
                "timestamp": datetime.now().isoformat(),
            }
            yield {"event": "health", "data": json.dumps(data)}
            await asyncio.sleep(5.0)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Exploit Engine SSE ─────────────────────────────────────────────


@router.get("/exploit/stream")
async def stream_exploits():
    """SSE stream for real-time exploit attempt events.

    Streams events from all active exploit attempts:
    - expert_selected
    - payload_generated
    - verification_started
    - verification_complete
    - attempt_complete
    """

    async def event_generator():
        sent_counts: dict[str, int] = {}

        while True:
            for attempt_id, stream_data in list(_active_streams.items()):
                events = stream_data.get("events", [])
                sent = sent_counts.get(attempt_id, 0)
                new_events = events[sent:]

                for event in new_events:
                    yield {
                        "event": event.get("type", "update"),
                        "data": json.dumps({
                            "attempt_id": attempt_id,
                            "timestamp": datetime.now().isoformat(),
                            **event.get("data", {}),
                        }),
                    }
                    sent_counts[attempt_id] = sent + 1

                if stream_data.get("status") in ("verified", "unverified", "failed", "refused_unsafe", "error"):
                    yield {
                        "event": "attempt_complete",
                        "data": json.dumps({
                            "attempt_id": attempt_id,
                            "status": stream_data["status"],
                        }),
                    }
                    sent_counts.pop(attempt_id, None)

            # Clean up completed streams
            done_ids = [
                aid for aid, sd in _active_streams.items()
                if sd.get("status") in ("verified", "unverified", "failed", "refused_unsafe", "error")
                and aid not in sent_counts
            ]
            for aid in done_ids:
                _active_streams.pop(aid, None)

            await asyncio.sleep(1.0)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/exploit/stream/{attempt_id}")
async def stream_single_exploit(attempt_id: str):
    """SSE stream for a single exploit attempt by ID."""

    async def event_generator():
        sent_events = 0

        while True:
            if attempt_id not in _active_streams:
                # Check if it's a completed attempt in storage
                from app.core.exploit import exploit_agent
                attempt = exploit_agent.get_attempt(attempt_id)
                if attempt:
                    yield {
                        "event": "complete",
                        "data": json.dumps({
                            "attempt_id": attempt_id,
                            "status": "completed",
                            "verified": attempt.get("verified", False),
                            "result": attempt,
                        }),
                    }
                else:
                    yield {
                        "event": "error",
                        "data": json.dumps({
                            "error": "Attempt not found",
                            "attempt_id": attempt_id,
                        }),
                    }
                break

            stream_data = _active_streams[attempt_id]
            events = stream_data.get("events", [])
            new_events = events[sent_events:]

            for event in new_events:
                yield {
                    "event": event.get("type", "update"),
                    "data": json.dumps({
                        "attempt_id": attempt_id,
                        "timestamp": datetime.now().isoformat(),
                        **event.get("data", {}),
                    }),
                }
                sent_events += 1

            if stream_data.get("status") in ("verified", "unverified", "failed", "refused_unsafe", "error"):
                yield {
                    "event": "done",
                    "data": json.dumps({
                        "attempt_id": attempt_id,
                        "status": stream_data["status"],
                        "final_result": stream_data.get("result", {}),
                    }),
                }
                _active_streams.pop(attempt_id, None)
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )