"""PITBULL API — Phase 2 intelligence endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from app.core.curiosity import curiosity_engine
from app.core.evolution import apply_event, get_evolution_summary, get_history
from app.core.mood import get_current_mood, trigger_mood, set_mood, Mood
from app.core.opinions import opinion_system
from app.core.consolidation import memory_consolidator
from app.core.activation import spreading_activation

logger = logging.getLogger(__name__)

router = APIRouter(tags=["intelligence"])


# ── Curiosity Engine ───────────────────────────────────────────────

@router.get("/curiosity/queue")
async def get_curiosity_queue(limit: int = 20) -> dict[str, Any]:
    """Get the current exploration queue ranked by curiosity score."""
    queue = curiosity_engine.get_queue(limit=limit)
    return {"queue": queue, "count": len(queue)}


@router.post("/curiosity/score")
async def score_target(target: str, context: dict | None = None) -> dict[str, Any]:
    """Score a single target's curiosity value."""
    score = curiosity_engine.score_target(target, context or {})
    return score.to_dict()


# ── Personality Evolution ──────────────────────────────────────────

@router.get("/personality/evolution")
async def get_personality_evolution(limit: int = 50) -> dict[str, Any]:
    """Get personality evolution history."""
    return {
        "history": get_history(limit),
        "summary": get_evolution_summary(),
    }


@router.post("/personality/evolve")
async def trigger_evolution(event_type: str, target: str = "", reason: str = "") -> dict[str, Any]:
    """Trigger a personality evolution event."""
    results = apply_event(event_type, target, reason)
    return {"adjustments": results, "count": len(results)}


# ── Mood System ────────────────────────────────────────────────────

@router.get("/mood")
async def get_mood() -> dict[str, Any]:
    """Get current mood and its effects."""
    return get_current_mood()


@router.post("/mood/trigger")
async def trigger_mood_change(event: str, reason: str = "") -> dict[str, Any]:
    """Trigger a mood change based on an event."""
    return trigger_mood(event, reason)


@router.post("/mood/set")
async def set_mood_manual(mood: str, reason: str = "") -> dict[str, Any]:
    """Manually set the mood."""
    try:
        m = Mood(mood)
        return set_mood(m, reason)
    except ValueError:
        return {"error": f"Invalid mood: {mood}. Valid: {[m.value for m in Mood]}"}


# ── Opinion System ─────────────────────────────────────────────────

@router.get("/opinions")
async def get_opinions(category: str | None = None, min_confidence: float = 0.0) -> dict[str, Any]:
    """Get all opinions."""
    opinions = opinion_system.get_opinions(category, min_confidence)
    return {"opinions": opinions, "count": len(opinions)}


@router.get("/opinions/{subject}")
async def get_opinion(subject: str) -> dict[str, Any]:
    """Get a specific opinion by subject."""
    opinion = opinion_system.get_opinion(subject)
    return opinion or {"error": "Opinion not found"}


@router.post("/opinions/form")
async def form_opinion(
    subject: str,
    opinion_text: str,
    evidence: str,
    confidence: float = 0.5,
    category: str = "general",
) -> dict[str, Any]:
    """Form or update an opinion."""
    return opinion_system.form_opinion(subject, opinion_text, evidence, confidence, category)


# ── Memory Consolidation ───────────────────────────────────────────

@router.post("/memory/consolidate")
async def consolidate_memories(since_hours: int = 24) -> dict[str, Any]:
    """Run memory consolidation cycle."""
    return memory_consolidator.consolidate(since_hours)


@router.get("/memory/semantic")
async def get_semantic_rules(limit: int = 50) -> dict[str, Any]:
    """Get all semantic memory rules."""
    rules = memory_consolidator.get_semantic_rules(limit)
    return {"rules": rules, "count": len(rules)}


# ── Spreading Activation ───────────────────────────────────────────

@router.post("/activation/trigger")
async def trigger_activation(
    node_id: int,
    node_type: str,
    label: str,
) -> dict[str, Any]:
    """Trigger spreading activation from a node."""
    activations = spreading_activation.activate_from_node(node_id, node_type, label)
    return {
        "activations": activations,
        "count": len(activations),
        "above_threshold": len([a for a in activations if a["activation"] >= 0.15]),
    }