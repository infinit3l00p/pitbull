"""PITBULL API — Phase 4 darknet exploration endpoints."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from fastapi import APIRouter

# Endpoint-level timeout for external API calls (seconds)
_ENDPOINT_TIMEOUT = 15.0

from app.collectors.tor import tor_controller
from app.collectors.onion import onion_collector
from app.collectors.opsec import opsec_detector
from app.collectors.relay import relay_census
from app.collectors.i2p import i2p_collector
from app.core.database import cypher_write

logger = logging.getLogger(__name__)

router = APIRouter(tags=["darknet"])


# ── Tor Control ────────────────────────────────────────────────────

@router.get("/tor/status")
async def tor_status() -> dict[str, Any]:
    """Get Tor connection status."""
    return tor_controller.get_info()


@router.post("/tor/new-circuit")
async def tor_new_circuit() -> dict[str, Any]:
    """Request a new Tor circuit (new identity)."""
    success = tor_controller.new_circuit()
    return {"success": success, "message": "New circuit requested" if success else "Failed"}


# ── Onion Service Discovery ────────────────────────────────────────

@router.get("/onion/discover")
async def discover_onions(query: str = "") -> dict[str, Any]:
    """Discover .onion services from directories."""
    try:
        onions = await asyncio.wait_for(onion_collector.discover_from_ahmia(query), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Onion discovery timed out (Ahmia may be unreachable)", "onions": [], "count": 0}
    return {"onions": onions, "count": len(onions)}


@router.post("/onion/classify")
async def classify_onion(url: str) -> dict[str, Any]:
    """Fetch and classify an .onion service."""
    result = await onion_collector.classify_onion(url)

    # OpSec analysis
    if result.get("online"):
        opsec = opsec_detector.analyze(result)
        result["opsec"] = opsec

    # Store in Neo4j
    cypher_write(
        "MERGE (o:OnionService {address: $addr}) "
        "SET o.title = $title, o.service_type = $type, o.online = $online, "
        "o.last_checked = datetime(), o.classified = $classified",
        {
            "addr": result.get("address", url),
            "title": result.get("title", ""),
            "type": result.get("service_type", "unknown"),
            "online": result.get("online", False),
            "classified": result.get("classified", False),
        },
    )

    if result.get("pgp_keys"):
        cypher_write(
            "MERGE (o:OnionService {address: $addr}) "
            "SET o.pgp_key = $pgp",
            {"addr": result.get("address", url), "pgp": result["pgp_keys"][0][:200]},
        )

    return result


@router.post("/onion/crawl")
async def crawl_onion(url: str, max_pages: int = 10) -> dict[str, Any]:
    """Crawl a .onion site through Tor."""
    try:
        return await asyncio.wait_for(tor_controller.crawl_onion(url, max_pages), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Onion crawl timed out (Tor circuit may be slow)", "url": url, "pages": []}


@router.post("/onion/extract")
async def extract_onions(text: str = "") -> dict[str, Any]:
    """Extract .onion addresses from text."""
    onions = await onion_collector.discover_from_text(text)
    return {"onions": onions, "count": len(onions)}


# ── OpSec ──────────────────────────────────────────────────────────

@router.post("/opsec/analyze")
async def opsec_analyze(fetch_result: dict[str, Any]) -> dict[str, Any]:
    """Analyze a fetched page for OpSec threats."""
    return opsec_detector.analyze(fetch_result)


# ── Relay Census ───────────────────────────────────────────────────

@router.get("/relays")
async def get_relays(limit: int = 100, search: str = "") -> dict[str, Any]:
    """Get Tor relay census data."""
    try:
        return await asyncio.wait_for(relay_census.get_relays(limit, search), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Tor relay census timed out (Onionoo may be unreachable)", "relays": [], "count": 0}


@router.get("/relays/summary")
async def relays_summary() -> dict[str, Any]:
    """Get Tor network summary."""
    try:
        return await asyncio.wait_for(relay_census.get_bridge_summary(), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Tor network summary timed out", "summary": {}}


@router.post("/relays/analyze")
async def analyze_relays(limit: int = 200) -> dict[str, Any]:
    """Analyze relay census data for patterns."""
    try:
        census = await asyncio.wait_for(relay_census.get_relays(limit), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Tor relay census timed out", "analysis": {}}
    if "error" in census:
        return census
    analysis = relay_census.analyze_census(census.get("relays", []))
    return analysis


# ── I2P ────────────────────────────────────────────────────────────

@router.get("/i2p/status")
async def i2p_status() -> dict[str, Any]:
    """Get I2P router status."""
    return i2p_collector.get_status()


@router.post("/i2p/fetch")
async def i2p_fetch(url: str) -> dict[str, Any]:
    """Fetch an I2P eepsite."""
    try:
        return await asyncio.wait_for(i2p_collector.fetch_eepsite(url), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "I2P fetch timed out (I2P tunnel may be slow)", "url": url}


@router.get("/i2p/discover")
async def i2p_discover() -> dict[str, Any]:
    """Discover I2P eepsites from directories."""
    try:
        eepsites = await asyncio.wait_for(i2p_collector.discover_from_dirs(), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "I2P discovery timed out", "eepsites": [], "count": 0}
    return {"eepsites": eepsites, "count": len(eepsites)}