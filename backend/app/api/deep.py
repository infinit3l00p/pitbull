"""PITBULL API — Phase 3 deep exploration endpoints."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter

# Endpoint-level timeout for external API calls (seconds)
_ENDPOINT_TIMEOUT = 15.0

from app.collectors.shodan import shodan_collector
from app.collectors.wayback import wayback_collector
from app.collectors.github import github_collector
from app.collectors.whois import whois_collector
from app.collectors.deepweb import deep_web_collector
from app.core.forensic import forensic_reconstructor

logger = logging.getLogger(__name__)

router = APIRouter(tags=["deep_exploration"])


# ── Shodan ─────────────────────────────────────────────────────────

@router.get("/shodan/info")
async def shodan_info() -> dict[str, Any]:
    """Get Shodan API account info."""
    return await shodan_collector.info()


@router.get("/shodan/host/{ip}")
async def shodan_host(ip: str) -> dict[str, Any]:
    """Get Shodan data for a specific IP."""
    try:
        return await asyncio.wait_for(shodan_collector.host_lookup(ip), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Shodan host lookup timed out", "ip": ip}


@router.get("/shodan/search")
async def shodan_search(query: str, page: int = 1) -> dict[str, Any]:
    """Search Shodan for devices."""
    try:
        return await asyncio.wait_for(shodan_collector.search(query, page), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Shodan search timed out", "query": query, "results": []}


# ── Wayback Machine ────────────────────────────────────────────────

@router.get("/wayback/snapshots/{domain}")
async def wayback_snapshots(domain: str, limit: int = 100) -> dict[str, Any]:
    """Get Wayback Machine snapshots for a domain."""
    try:
        return await asyncio.wait_for(wayback_collector.get_snapshots(domain, limit), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Wayback Machine request timed out", "domain": domain, "snapshots": []}


@router.get("/wayback/deleted/{domain}")
async def wayback_deleted(domain: str, limit: int = 200) -> dict[str, Any]:
    """Find deleted pages from Wayback Machine."""
    try:
        return await asyncio.wait_for(wayback_collector.find_deleted_pages(domain, limit), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Wayback Machine request timed out", "domain": domain, "deleted": []}


@router.get("/wayback/changes/{domain}")
async def wayback_changes(domain: str, limit: int = 200) -> dict[str, Any]:
    """Find status code changes over time from Wayback Machine."""
    try:
        return await asyncio.wait_for(wayback_collector.find_status_code_changes(domain, limit), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Wayback Machine request timed out", "domain": domain, "changes": []}


# ── GitHub Recon ───────────────────────────────────────────────────

@router.get("/github/search/code")
async def github_search_code(query: str, per_page: int = 30) -> dict[str, Any]:
    """Search GitHub code."""
    return await github_collector.search_code(query, per_page)


@router.get("/github/search/repos")
async def github_search_repos(query: str, per_page: int = 30) -> dict[str, Any]:
    """Search GitHub repositories."""
    return await github_collector.search_repos(query, per_page)


@router.get("/github/secrets/{domain}")
async def github_secrets(domain: str) -> dict[str, Any]:
    """Search GitHub for leaked secrets related to a domain."""
    try:
        return await asyncio.wait_for(github_collector.search_secrets(domain), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "GitHub API request timed out", "domain": domain, "secrets": []}


@router.get("/github/infrastructure/{domain}")
async def github_infrastructure(domain: str) -> dict[str, Any]:
    """Search GitHub for infrastructure mentions."""
    return await github_collector.search_infrastructure(domain)


@router.get("/github/org/{org}")
async def github_org_repos(org: str) -> dict[str, Any]:
    """Get public repos for a GitHub organization."""
    return await github_collector.get_org_repos(org)


# ── WHOIS ──────────────────────────────────────────────────────────

@router.get("/whois/{domain}")
async def whois_lookup(domain: str) -> dict[str, Any]:
    """Perform a WHOIS lookup."""
    return await whois_collector.lookup(domain)


@router.get("/whois/{domain}/timeline")
async def whois_timeline(domain: str) -> dict[str, Any]:
    """Get WHOIS registration timeline."""
    return await whois_collector.get_registration_timeline(domain)


# ── Deep Web Probing ───────────────────────────────────────────────

@router.post("/deepweb/probe")
async def deepweb_probe(url: str) -> dict[str, Any]:
    """Probe a URL for deep web content (admin panels, APIs, configs)."""
    try:
        return await asyncio.wait_for(deep_web_collector.probe(url), timeout=_ENDPOINT_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": "Deep web probe timed out", "url": url, "findings": []}


# ── Forensic Reconstruction ────────────────────────────────────────

@router.get("/forensic/timeline/{target}")
async def forensic_timeline(target: str) -> dict[str, Any]:
    """Build a forensic timeline for a target."""
    return forensic_reconstructor.build_timeline(target)


@router.get("/forensic/genealogy/{target}")
async def forensic_genealogy(target: str, max_depth: int = 3) -> dict[str, Any]:
    """Trace infrastructure genealogy for a target."""
    return forensic_reconstructor.infrastructure_genealogy(target, max_depth)


@router.get("/forensic/attribution/{target}")
async def forensic_attribution(target: str) -> dict[str, Any]:
    """Analyze attribution indicators for a target."""
    return forensic_reconstructor.attribution_analysis(target)