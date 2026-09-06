"""PITBULL API — personality endpoints."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter

from app.config import settings
from app.models import PersonalityState

logger = logging.getLogger(__name__)

router = APIRouter(tags=["personality"])

STATE_FILE = Path(settings.state_dir) / "personality.json"


def _load_state() -> PersonalityState:
    """Load personality state from disk or defaults."""
    if STATE_FILE.exists():
        data = json.loads(STATE_FILE.read_text())
        return PersonalityState(**data)
    return PersonalityState(
        openness=settings.personality_openness,
        conscientiousness=settings.personality_conscientiousness,
        extraversion=settings.personality_extraversion,
        agreeableness=settings.personality_agreeableness,
        neuroticism=settings.personality_neuroticism,
    )


def _save_state(state: PersonalityState) -> None:
    """Save personality state to disk."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(state.model_dump_json(indent=2))


@router.get("/")
async def get_personality() -> dict[str, Any]:
    """Get current personality state."""
    state = _load_state()
    return state.model_dump()


@router.patch("/")
async def update_personality(updates: dict[str, Any]) -> dict[str, Any]:
    """Update personality traits (called by evolution system)."""
    state = _load_state()

    # Clamp trait values to [0, 1]
    for trait in ["openness", "conscientiousness", "extraversion", "agreeableness", "neuroticism"]:
        if trait in updates:
            new_val = max(0.0, min(1.0, float(updates[trait])))
            updates[trait] = round(new_val, 4)

    updated = state.model_copy(update=updates)
    _save_state(updated)

    logger.info(f"Personality updated: {updates}")
    return updated.model_dump()


@router.get("/history")
async def personality_history() -> dict[str, Any]:
    """Get personality evolution history (TODO: track changes over time)."""
    state = _load_state()
    return {
        "current": state.model_dump(),
        "history": [],
        "message": "Personality evolution tracking will be implemented in Phase 2",
    }