"""PITBULL API — Phase 5 evolution endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from app.core.mistakes import mistake_learner
from app.core.patterns import pattern_discovery
from app.core.tool_gen import tool_generator
from app.core.knowledge import knowledge_expander
from app.core.drift import personality_drift

logger = logging.getLogger(__name__)

router = APIRouter(tags=["evolution"])


# ── Mistake Learning ───────────────────────────────────────────────

@router.get("/mistakes")
async def get_mistakes(limit: int = 50) -> dict[str, Any]:
    """Get recent mistakes."""
    return {"mistakes": mistake_learner.get_mistakes(limit), "count": len(mistake_learner.get_mistakes(limit))}


@router.get("/mistakes/lessons")
async def get_lessons() -> dict[str, Any]:
    """Get all unique lessons learned."""
    lessons = mistake_learner.get_lessons()
    return {"lessons": lessons, "count": len(lessons)}


@router.get("/mistakes/stats")
async def mistake_stats() -> dict[str, Any]:
    """Get mistake statistics."""
    return mistake_learner.get_mistake_stats()


@router.post("/mistakes/log")
async def log_mistake(
    mistake_type: str,
    target: str,
    situation: str,
    what_pitbull_did: str,
    what_should_have_done: str,
    lesson: str,
    trait_suggestion: str = "",
    severity: str = "medium",
) -> dict[str, Any]:
    """Log a mistake."""
    return mistake_learner.log_mistake(
        mistake_type, target, situation, what_pitbull_did,
        what_should_have_done, lesson, trait_suggestion, severity,
    )


@router.get("/mistakes/check")
async def check_past_mistakes(target: str, situation: str) -> dict[str, Any]:
    """Check if current situation resembles a past mistake."""
    return {"relevant_mistakes": mistake_learner.check_past_mistakes(target, situation)}


# ── Pattern Discovery ──────────────────────────────────────────────

@router.post("/patterns/discover")
async def discover_patterns(min_targets: int = 10) -> dict[str, Any]:
    """Run pattern discovery across all exploration data."""
    return pattern_discovery.discover_patterns(min_targets)


@router.get("/patterns/gaps")
async def knowledge_gaps() -> dict[str, Any]:
    """Identify knowledge gaps."""
    gaps = pattern_discovery.identify_knowledge_gaps()
    return {"gaps": gaps, "count": len(gaps)}


# ── Tool Generation ────────────────────────────────────────────────

@router.get("/tools")
async def get_tools() -> dict[str, Any]:
    """Get all generated tools."""
    tools = tool_generator.get_tools()
    return {"tools": tools, "count": len(tools)}


@router.get("/tools/{name}")
async def get_tool(name: str) -> dict[str, Any]:
    """Get a specific tool by name."""
    tool = tool_generator.get_tool(name)
    return tool or {"error": "Tool not found"}


@router.post("/tools/generate")
async def generate_tool(gap: str, context: str = "", target: str = "") -> dict[str, Any]:
    """Generate a custom tool using LLM."""
    return await tool_generator.generate_tool(gap, context, target)


# ── Knowledge Expansion ────────────────────────────────────────────

@router.post("/knowledge/study-cves")
async def study_cves(days: int = 30, max_results: int = 20) -> dict[str, Any]:
    """Study recent CVEs from NVD."""
    return await knowledge_expander.study_recent_cves(days, max_results)


@router.post("/knowledge/study-tech")
async def study_tech(technology: str, max_results: int = 10) -> dict[str, Any]:
    """Study CVEs for a specific technology."""
    return await knowledge_expander.study_cve_for_tech(technology, max_results)


@router.get("/knowledge/study-plan")
async def study_plan() -> dict[str, Any]:
    """Get a study plan based on knowledge gaps."""
    plan = knowledge_expander.get_study_plan()
    return {"plan": plan, "count": len(plan)}


@router.get("/knowledge/stats")
async def knowledge_stats() -> dict[str, Any]:
    """Get knowledge base statistics."""
    return knowledge_expander.get_knowledge_stats()


# ── Personality Drift ──────────────────────────────────────────────

@router.post("/personality/drift")
async def calculate_drift(days: int = 7) -> dict[str, Any]:
    """Calculate and apply personality drift based on recent experience."""
    return personality_drift.calculate_drift(days)


@router.get("/personality/drift/history")
async def drift_history(limit: int = 20) -> dict[str, Any]:
    """Get personality drift history."""
    history = personality_drift.get_drift_history(limit)
    return {"history": history, "count": len(history)}