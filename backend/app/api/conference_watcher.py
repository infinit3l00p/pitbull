"""PITBULL API — Conference Watcher endpoints.

Tracks Asian security conferences, arXiv research papers, and a knowledge
base of security techniques.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query

from app.conference_watcher.conferences import (
    get_all_conferences,
    get_upcoming_conferences,
    get_conference,
    update_conference_status,
)
from app.conference_watcher.paper_monitor import PaperMonitor
from app.conference_watcher.knowledge_base import KnowledgeBase
from app.conference_watcher.scheduler import ConferenceWatcher

logger = logging.getLogger(__name__)

router = APIRouter(tags=["conference_watcher"])

# ── Singletons ─────────────────────────────────────────────────────

_paper_monitor: PaperMonitor | None = None
_knowledge_base: KnowledgeBase | None = None
_watcher: ConferenceWatcher | None = None


def _get_paper_monitor() -> PaperMonitor:
    global _paper_monitor
    if _paper_monitor is None:
        _paper_monitor = PaperMonitor()
    return _paper_monitor


def _get_knowledge_base() -> KnowledgeBase:
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
    return _knowledge_base


def _get_watcher() -> ConferenceWatcher:
    global _watcher
    if _watcher is None:
        _watcher = ConferenceWatcher()
    return _watcher


# ── Conference Endpoints ───────────────────────────────────────────


@router.get("/")
async def list_conferences() -> dict[str, Any]:
    """List all tracked conferences with current status."""
    conferences = get_all_conferences()
    return {
        "total": len(conferences),
        "conferences": conferences,
    }


@router.get("/upcoming")
async def upcoming_conferences(
    days: int = Query(30, ge=1, le=365, description="Number of days to look ahead"),
) -> dict[str, Any]:
    """Get upcoming conferences within the next N days."""
    conferences = get_upcoming_conferences(days=days)
    return {
        "days": days,
        "count": len(conferences),
        "conferences": conferences,
    }


# ── Paper Endpoints ────────────────────────────────────────────────


@router.get("/papers")
async def list_papers(
    days: int = Query(7, ge=1, le=365, description="Papers from last N days"),
) -> dict[str, Any]:
    """List tracked research papers from the last N days."""
    monitor = _get_paper_monitor()
    papers = await monitor.get_recent_papers(days=days)
    return {
        "count": len(papers),
        "days": days,
        "papers": papers,
    }


@router.get("/papers/search")
async def search_papers(
    q: str = Query(..., min_length=1, description="Search query"),
) -> dict[str, Any]:
    """Search stored research papers by keyword."""
    monitor = _get_paper_monitor()
    papers = await monitor.search_papers(q)
    return {
        "query": q,
        "count": len(papers),
        "papers": papers,
    }


@router.post("/papers/scan")
async def scan_papers(
    max_per_keyword: int = Query(5, ge=1, le=20, description="Max papers per keyword"),
) -> dict[str, Any]:
    """Trigger an arXiv scan for new security papers."""
    monitor = _get_paper_monitor()
    papers = await monitor.scan_keywords(max_per_keyword=max_per_keyword)
    return {
        "status": "complete",
        "papers_found": len(papers),
        "papers": [
            {
                "paper_id": p.get("paper_id", ""),
                "title": p.get("title", ""),
                "arxiv_url": p.get("arxiv_url", ""),
                "published": p.get("published", ""),
            }
            for p in papers
        ],
    }


# ── Knowledge Base Endpoints ───────────────────────────────────────


@router.get("/knowledge")
async def list_knowledge(
    technique_type: str | None = Query(None, description="Filter by technique type"),
    source: str | None = Query(None, description="Filter by source"),
    tag: str | None = Query(None, description="Filter by tag"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """List knowledge base entries with optional filters."""
    kb = _get_knowledge_base()
    entries = await kb.get_entries(
        technique_type=technique_type,
        source=source,
        tag=tag,
        limit=limit,
        offset=offset,
    )
    return {
        "count": len(entries),
        "entries": entries,
    }


@router.get("/knowledge/search")
async def search_knowledge(
    q: str = Query(..., min_length=1, description="Search query"),
) -> dict[str, Any]:
    """Search the knowledge base."""
    kb = _get_knowledge_base()
    entries = await kb.search_entries(q)
    return {
        "query": q,
        "count": len(entries),
        "entries": entries,
    }


@router.get("/knowledge/{entry_id}")
async def knowledge_entry(entry_id: str) -> dict[str, Any]:
    """Get a specific knowledge base entry by ID."""
    kb = _get_knowledge_base()
    entry = await kb.get_entry(entry_id)
    if entry is None:
        return {"error": "Entry not found", "entry_id": entry_id}
    return entry


# ── Scan & Stats Endpoints ─────────────────────────────────────────


@router.post("/scan")
async def trigger_full_scan() -> dict[str, Any]:
    """Trigger a full scan: conferences + papers + knowledge base update."""
    watcher = _get_watcher()
    summary = await watcher.run_full_scan()
    return summary


@router.get("/stats")
async def stats() -> dict[str, Any]:
    """Get statistics: total conferences, papers, KB entries, by category."""
    conferences = get_all_conferences()
    conf_by_status = {"upcoming": 0, "ongoing": 0, "past": 0}
    conf_by_tier = {1: 0, 2: 0}
    for c in conferences:
        status = c.get("status", "upcoming")
        if status in conf_by_status:
            conf_by_status[status] += 1
        tier = c.get("tier", 2)
        conf_by_tier[tier] = conf_by_tier.get(tier, 0) + 1

    monitor = _get_paper_monitor()
    recent_papers = await monitor.get_recent_papers(days=365)

    kb = _get_knowledge_base()
    kb_stats = await kb.get_stats()

    return {
        "conferences": {
            "total": len(conferences),
            "by_status": conf_by_status,
            "by_tier": conf_by_tier,
        },
        "papers": {
            "total_stored": len(recent_papers),
        },
        "knowledge_base": {
            "total": kb_stats.get("total", 0),
            "types": kb_stats.get("types", []),
            "sources": kb_stats.get("sources", []),
        },
    }


@router.get("/calendar")
async def calendar_view(
    months: int = Query(6, ge=1, le=12, description="Number of months to show"),
) -> dict[str, Any]:
    """Calendar view of upcoming events as JSON."""
    update_conference_status()
    # Get all upcoming conferences sorted by date
    conferences = sorted(
        [c for c in get_all_conferences() if c.get("status") in ("upcoming", "ongoing")],
        key=lambda c: c["start_date"],
    )

    # Group by month
    calendar: dict[str, list[dict[str, Any]]] = {}
    for conf in conferences:
        month_key = conf["start_date"][:7]  # YYYY-MM
        if month_key not in calendar:
            calendar[month_key] = []
        calendar[month_key].append({
            "id": conf["id"],
            "name": conf["name"],
            "location": conf["location"],
            "start_date": conf["start_date"],
            "end_date": conf["end_date"],
            "status": conf["status"],
            "days_until": conf.get("days_until", 0),
            "tier": conf["tier"],
            "focus_areas": conf["focus_areas"],
            "website": conf["website"],
        })

    return {
        "months": months,
        "total_events": len(conferences),
        "calendar": calendar,
    }

# ── Conference Details (MUST be last — catch-all) ──────────────────


@router.get("/{name}")
async def conference_details(name: str) -> dict[str, Any]:
    """Get details for a specific conference by name (partial match)."""
    conf = get_conference(name)
    if conf is None:
        return {"error": "Conference not found", "query": name}
    return conf
