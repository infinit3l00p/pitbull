"""PITBULL API — Cerberus LLM-Guided Zero-Day Discovery endpoints.

Provides target analysis, fuzzing campaign management, vulnerability
findings CRUD, report generation, export, analytics, and SSE feed.

DEFENSIVE RESEARCH ONLY — discovery and reporting, no weaponization.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.cerberus.target_analyzer import TargetAnalyzer
from app.cerberus.llm_fuzzer import get_fuzzer
from app.cerberus.crash_triage import get_triage
from app.cerberus.vuln_library import get_library

logger = logging.getLogger(__name__)

router = APIRouter(tags=["cerberus"])
# Public router for SSE feed (EventSource can't send API key headers)
public_router = APIRouter(tags=["cerberus"])


# ── Request/Response models ─────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    target: str = Field(..., description="Binary path, host:port, or URL")
    target_type: str = Field("binary", description="binary | protocol | api")


class FuzzStartRequest(BaseModel):
    target: str = Field(..., description="Binary path, host:port, or URL")
    strategy: str = Field("mutation", description="mutation | grammar | semantic | path-guided | hybrid")
    iterations: int = Field(1000, ge=1, le=100000)
    delay_ms: int = Field(100, ge=0, le=60000)
    target_type: str = Field("binary", description="binary | protocol | api")


class FuzzStopRequest(BaseModel):
    pass


class UpdateFindingRequest(BaseModel):
    status: str = Field(..., description="new | confirmed | reported | fixed | false_positive")


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Cerberus engine status, active campaigns, total findings."""
    fuzzer = get_fuzzer()
    library = get_library()
    campaign = fuzzer.get_status()

    findings = library.get_findings()

    return {
        "status": "ready",
        "active_campaign": campaign,
        "total_findings": len(findings),
        "critical_findings": sum(1 for f in findings if f.get("severity") == "Critical"),
        "high_findings": sum(1 for f in findings if f.get("severity") == "High"),
        "medium_findings": sum(1 for f in findings if f.get("severity") == "Medium"),
        "low_findings": sum(1 for f in findings if f.get("severity") == "Low"),
        "new_findings": sum(1 for f in findings if f.get("status") == "new"),
        "confirmed_findings": sum(1 for f in findings if f.get("status") == "confirmed"),
        "reported_findings": sum(1 for f in findings if f.get("status") == "reported"),
        "fixed_findings": sum(1 for f in findings if f.get("status") == "fixed"),
    }


@router.post("/analyze")
async def analyze_target(req: AnalyzeRequest) -> dict[str, Any]:
    """Analyze a target (binary, protocol, or API)."""
    analyzer = TargetAnalyzer()
    result = await analyzer.analyze(req.target, req.target_type)
    return result


@router.post("/fuzz/start")
async def start_fuzzing(req: FuzzStartRequest) -> dict[str, Any]:
    """Start a fuzzing campaign."""
    fuzzer = get_fuzzer()

    # Stop any existing campaign
    if fuzzer.get_status() and fuzzer.get_status().get("status") == "running":
        fuzzer.stop()

    # Run fuzzing in background
    asyncio.create_task(
        fuzzer.fuzz(
            target=req.target,
            strategy=req.strategy,
            iterations=req.iterations,
            delay_ms=req.delay_ms,
            target_type=req.target_type,
        )
    )

    return {
        "status": "started",
        "target": req.target,
        "strategy": req.strategy,
        "iterations": req.iterations,
        "message": f"Fuzzing campaign started — {req.strategy} strategy, {req.iterations} iterations",
    }


@router.post("/fuzz/stop")
async def stop_fuzzing() -> dict[str, Any]:
    """Stop the active fuzzing campaign."""
    fuzzer = get_fuzzer()
    fuzzer.stop()
    return {"status": "stopped", "message": "Fuzzing campaign stopped"}


@router.get("/fuzz/status")
async def fuzz_status() -> dict[str, Any]:
    """Get current fuzzing campaign status."""
    fuzzer = get_fuzzer()
    status = fuzzer.get_status()
    if status is None:
        return {"status": "idle", "message": "No active campaign"}
    return status


@router.get("/findings")
async def list_findings(
    severity: str | None = None,
    target: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """List all discovered vulnerabilities."""
    library = get_library()
    filter: dict[str, Any] = {"limit": limit}
    if severity:
        filter["severity"] = severity
    if target:
        filter["target"] = target
    if status:
        filter["status"] = status

    findings = library.get_findings(filter)
    return {"findings": findings, "total": len(findings)}


@router.get("/findings/export")
async def export_findings(format: str = "json") -> dict[str, Any]:
    """Export findings as JSON, CSV, or markdown."""
    library = get_library()
    data = library.export_findings(format)
    return {"format": format, "data": data}


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str) -> dict[str, Any]:
    """Get specific finding details."""
    library = get_library()
    finding = library.get_finding(finding_id)
    if finding is None:
        return {"error": "Finding not found", "finding_id": finding_id}
    return finding


@router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, req: UpdateFindingRequest) -> dict[str, Any]:
    """Update finding status."""
    library = get_library()
    result = library.update_finding_status(finding_id, req.status)
    return result


@router.get("/findings/{finding_id}/report")
async def generate_report(finding_id: str) -> dict[str, Any]:
    """Generate a formal vulnerability report."""
    library = get_library()
    report = library.generate_report(finding_id)
    return {"finding_id": finding_id, "report": report, "format": "markdown"}


@router.get("/cwe/classes")
async def get_cwe_classes() -> dict[str, Any]:
    """List CWE vulnerability classes."""
    classes = get_triage().get_cwe_classes()
    return {"classes": classes, "total": len(classes)}


@router.get("/analytics")
async def get_analytics() -> dict[str, Any]:
    """Get analytics: findings by severity, CWE, target, date."""
    library = get_library()
    return library.get_analytics()


# ── SSE Feed (public, no API key) ────────────────────────────────────


@public_router.get("/feed")
async def cerberus_feed():
    """Server-Sent Events stream for real-time fuzzing events."""
    fuzzer = get_fuzzer()
    sent_events = 0

    async def event_generator():
        nonlocal sent_events
        while True:
            campaign = fuzzer.get_status()
            if campaign is None:
                yield f"event: status\ndata: {json.dumps({'status': 'idle'})}\n\n"
                await asyncio.sleep(2)
                continue

            # Send new events
            events = campaign.get("events", [])
            new_events = events[sent_events:]
            for event in new_events:
                payload = json.dumps({
                    "timestamp": event.get("timestamp", datetime.now().isoformat()),
                    "type": event.get("type"),
                    "data": event.get("data"),
                    "campaign_id": campaign.get("campaign_id"),
                })
                yield f"event: {event.get('type', 'log')}\ndata: {payload}\n\n"
                sent_events += 1

            # Send status update
            status_payload = json.dumps({
                "status": campaign.get("status"),
                "iterations_run": campaign.get("iterations_run", 0),
                "crashes_found": campaign.get("crashes_found", 0),
                "unique_crashes": campaign.get("unique_crashes", 0),
                "hangs_found": campaign.get("hangs_found", 0),
                "campaign_id": campaign.get("campaign_id"),
            })
            yield f"event: status\ndata: {status_payload}\n\n"

            # If campaign is done, send done event
            if campaign.get("status") in ("completed", "stopped"):
                done_payload = json.dumps({
                    "campaign_id": campaign.get("campaign_id"),
                    "status": campaign.get("status"),
                    "total_iterations": campaign.get("iterations_run"),
                    "total_crashes": campaign.get("crashes_found"),
                    "unique_crashes": campaign.get("unique_crashes"),
                })
                yield f"event: done\ndata: {done_payload}\n\n"
                sent_events = 0  # Reset for next campaign

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )