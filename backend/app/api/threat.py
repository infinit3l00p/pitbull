"""PITBULL API — Threat Intelligence endpoints (CVE, OWASP, ATT&CK)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from app.core.threat_intel import threat_intelligence

logger = logging.getLogger(__name__)

router = APIRouter(tags=["threat_intelligence"])


# ── CVE Management ─────────────────────────────────────────────────

@router.post("/threat/cves/update")
async def update_cves(days: int = 7, max_results: int = 50) -> dict[str, Any]:
    """Fetch and store recent CVEs from NVD."""
    return await threat_intelligence.update_cves(days, max_results)


@router.post("/threat/cves/update-tech")
async def update_tech_cves(technologies: str, max_per_tech: int = 10) -> dict[str, Any]:
    """Fetch CVEs for specific technologies (comma-separated)."""
    tech_list = [t.strip() for t in technologies.split(",") if t.strip()]
    return await threat_intelligence.update_tech_cves(tech_list, max_per_tech)


@router.get("/threat/cves")
async def get_cves(limit: int = 50, severity: str | None = None) -> dict[str, Any]:
    """Get stored CVEs from Neo4j."""
    from app.core.database import cypher_read
    if severity:
        results = cypher_read(
            "MATCH (c:CVE {severity: $sev}) RETURN c ORDER BY c.cvss_v3_score DESC LIMIT $limit",
            {"sev": severity.upper(), "limit": limit},
        )
    else:
        results = cypher_read(
            "MATCH (c:CVE) RETURN c ORDER BY c.cvss_v3_score DESC LIMIT $limit",
            {"limit": limit},
        )
    cves = []
    for row in results:
        c = row.get("c", {})
        cves.append({
            "id": c.get("cve_id", ""),
            "description": c.get("description", "")[:200],
            "cvss_score": c.get("cvss_v3_score", 0),
            "severity": c.get("severity", ""),
            "technology": c.get("technology", ""),
            "published": c.get("published_date", ""),
            "attack_techniques": c.get("attack_techniques", []),
        })
    return {"cves": cves, "count": len(cves)}


# ── OWASP ──────────────────────────────────────────────────────────

@router.post("/threat/owasp/load")
async def load_owasp() -> dict[str, Any]:
    """Load OWASP Top 10:2025 knowledge into Neo4j."""
    return threat_intelligence.load_owasp_knowledge()


@router.get("/threat/owasp")
async def get_owasp() -> dict[str, Any]:
    """Get all OWASP categories."""
    categories = threat_intelligence.get_owasp_categories()
    return {"categories": categories, "count": len(categories)}


@router.post("/threat/owasp/map")
async def map_owasp(target: str) -> dict[str, Any]:
    """Map exploration findings to OWASP categories."""
    return threat_intelligence.map_mission_to_owasp(target)


# ── Full Update ────────────────────────────────────────────────────

@router.post("/threat/update-all")
async def full_threat_update() -> dict[str, Any]:
    """Run a full threat intelligence update — CVEs + OWASP + tech CVEs."""
    return await threat_intelligence.full_update()


# ── Stats ──────────────────────────────────────────────────────────

@router.get("/threat/stats")
async def threat_stats() -> dict[str, Any]:
    """Get threat intelligence statistics."""
    return threat_intelligence.get_threat_stats()