"""PITBULL API — ntopng network traffic intelligence endpoints.

Provides real-time traffic monitoring, flow analysis, and network alerts
sourced from ntopng via the NtopngCollector.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from app.collectors.ntopng import NtopngCollector

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ntopng"])

# Singleton collector instance
_collector: NtopngCollector | None = None


def _get_collector() -> NtopngCollector:
    """Get or create the NtopngCollector singleton."""
    global _collector
    if _collector is None:
        _collector = NtopngCollector()
    return _collector


def init_collector() -> NtopngCollector:
    """Initialize the collector (called from main.py lifespan)."""
    global _collector
    if _collector is None:
        _collector = NtopngCollector()
    return _collector


# ── Status ────────────────────────────────────────────────────────

@router.get("/ntopng/status")
async def ntopng_status() -> dict[str, Any]:
    """Get ntopng collector status and stats."""
    collector = _get_collector()
    return collector.get_stats()


# ── Top Talkers ────────────────────────────────────────────────────

@router.get("/ntopng/top-talkers")
async def ntopng_top_talkers(limit: int = 20) -> dict[str, Any]:
    """Get top hosts by traffic volume."""
    collector = _get_collector()
    talkers = collector.get_top_talkers(limit=limit)
    return {"count": len(talkers), "hosts": talkers}


# ── Network Alerts ────────────────────────────────────────────────

@router.get("/ntopng/alerts")
async def ntopng_alerts(limit: int = 50) -> dict[str, Any]:
    """Get recent network alerts from ntopng."""
    collector = _get_collector()
    alerts = collector.get_recent_alerts(limit=limit)
    return {"count": len(alerts), "alerts": alerts}


# ── Suspicious Hosts ──────────────────────────────────────────────

@router.get("/ntopng/suspicious")
async def ntopng_suspicious() -> dict[str, Any]:
    """Get hosts flagged by ntopng alerts."""
    collector = _get_collector()
    hosts = collector.get_suspicious_hosts()
    return {"count": len(hosts), "hosts": hosts}


# ── Live Flows ────────────────────────────────────────────────────

@router.get("/ntopng/flows")
async def ntopng_live_flows(limit: int = 100) -> dict[str, Any]:
    """Get recent flows stored in the graph."""
    from app.core.database import cypher_read
    records = cypher_read("""
        MATCH (src:Host)-[:SENT]->(f:Flow)-[:TO]->(dst:Host)
        RETURN src.ip AS src_ip, dst.ip AS dst_ip, f.protocol AS protocol,
               f.bytes AS bytes, f.packets AS packets, f.port AS port,
               f.last_seen AS last_seen
        ORDER BY f.last_seen DESC
        LIMIT $limit
    """, {"limit": limit})
    flows = [dict(r) for r in records]
    return {"count": len(flows), "flows": flows}