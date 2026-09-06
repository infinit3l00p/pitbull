"""Sentinel investigation endpoint — aggregates OSINT data for an attacker IP."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter
from app.core.database import cypher_read
from app.core.sentinel.sentinel_engine import SentinelEngine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sentinel"])

_engine: SentinelEngine | None = None

def _get_engine() -> SentinelEngine:
    global _engine
    if _engine is None:
        _engine = SentinelEngine()
    return _engine


@router.get("/sentinel/investigate/{ip}")
async def investigate_ip(ip: str) -> dict[str, Any]:
    """Aggregate all PITBULL data about an attacker IP.

    Pulls from:
    - Sentinel attacker profile (attack history, techniques)
    - Neo4j graph (any nodes connected to this IP)
    - Shodan host lookup (open ports, services, geo)
    - PITBULL memory graph (past encounters)
    """
    engine = _get_engine()
    result: dict[str, Any] = {"ip": ip, "sources": {}}

    # 1. Sentinel attacker profile
    attackers = engine.get_attackers()
    profile = next((a for a in attackers if a.get("ip") == ip), None)
    if profile:
        result["sources"]["sentinel"] = profile
    else:
        result["sources"]["sentinel"] = None

    # 2. Recent attacks from this IP
    attacks = engine.get_recent_attacks(limit=200)
    ip_attacks = [a for a in attacks if a.get("source_ip") == ip]
    result["sources"]["attacks"] = ip_attacks[:20]

    # 3. Neo4j — find any nodes related to this IP
    try:
        nodes = cypher_read(
            "MATCH (n) WHERE n.ip = $ip OR n.address = $ip OR n.source_ip = $ip "
            "RETURN labels(n) AS labels, properties(n) AS props LIMIT 20",
            {"ip": ip},
        )
        result["sources"]["neo4j"] = [
            {"labels": r["labels"], "props": r["props"]} for r in nodes
        ]
    except Exception as e:
        result["sources"]["neo4j"] = {"error": str(e)}

    # 4. Neo4j — attack events stored for this IP
    try:
        events = cypher_read(
            "MATCH (a:Attacker {ip: $ip})-[:PERFORMED]->(e:AttackEvent) "
            "RETURN e ORDER BY e.timestamp DESC LIMIT 20",
            {"ip": ip},
        )
        result["sources"]["neo4j_events"] = [r["e"] for r in events]
    except Exception as e:
        result["sources"]["neo4j_events"] = {"error": str(e)}

    # 5. Shodan host lookup (async, with timeout)
    try:
        from app.collectors.shodan import shodan_collector
        shodan_data = await asyncio.wait_for(
            shodan_collector.host_lookup(ip), timeout=10.0
        )
        result["sources"]["shodan"] = shodan_data
    except asyncio.TimeoutError:
        result["sources"]["shodan"] = {"error": "Shodan lookup timed out"}
    except Exception as e:
        result["sources"]["shodan"] = {"error": str(e)}

    # 6. Summary
    attack_count = len(ip_attacks)
    techniques = list(set(a.get("technique_id", "") for a in ip_attacks if a.get("technique_id")))
    attack_types = list(set(a.get("attack_type", "") for a in ip_attacks if a.get("attack_type")))
    is_blocked = profile.get("is_blocked", False) if profile else False

    result["summary"] = {
        "ip": ip,
        "total_attacks": attack_count,
        "attack_types": attack_types,
        "techniques_used": techniques,
        "is_blocked": is_blocked,
        "first_seen": profile.get("first_seen") if profile else None,
        "last_seen": profile.get("last_seen") if profile else None,
    }

    return result