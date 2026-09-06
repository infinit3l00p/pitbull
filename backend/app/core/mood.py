"""PITBULL Mood System — transient emotional states.

Moods are temporary states affected by recent events. They modify
exploration behavior (aggressiveness, thoroughness, strategy).

Academic basis:
- PersonaAgent (ACL 2026): mood as transient personality modifier
- Browsing Like Human (ACL 2025): dual-process thinking affected by state
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from app.config import settings
from app.api.personality import _load_state, _save_state

logger = logging.getLogger(__name__)

MOOD_FILE = Path(settings.state_dir) / "mood.json"


class Mood(str, Enum):
    NEUTRAL = "neutral"
    EXCITED = "excited"
    BORED = "bored"
    FRUSTRATED = "frustrated"
    CAUTIOUS = "cautious"
    SATISFIED = "satisfied"
    CURIOUS = "curious"


# Mood durations (minutes)
MOOD_DURATIONS: dict[Mood, int] = {
    Mood.NEUTRAL: 0,       # no expiry
    Mood.EXCITED: 30,
    Mood.BORED: 60,
    Mood.FRUSTRATED: 45,
    Mood.CAUTIOUS: 60,
    Mood.SATISFIED: 90,
    Mood.CURIOUS: 45,
}


# Mood effects on exploration parameters
MOOD_EFFECTS: dict[Mood, dict[str, float]] = {
    Mood.NEUTRAL: {},
    Mood.EXCITED: {
        "rate_multiplier": 1.3,    # faster requests
        "depth_bonus": 1,          # explore deeper
        "novelty_bias": 0.2,       # prefer novel targets
    },
    Mood.BORED: {
        "rate_multiplier": 0.8,
        "novelty_bias": 0.4,       # seek novelty harder
        "unusual_approach": 0.3,   # try unusual techniques
    },
    Mood.FRUSTRATED: {
        "rate_multiplier": 0.5,    # slow down
        "strategy_switch": 1.0,    # switch strategy entirely
        "neuroticism_boost": 0.1,
    },
    Mood.CAUTIOUS: {
        "rate_multiplier": 0.7,
        "double_check": 1.0,       # verify findings more
        "false_positive_threshold": 0.8,  # higher bar for reporting
    },
    Mood.SATISFIED: {
        "rate_multiplier": 1.0,
        "documentation_boost": 1.0, # thorough documentation
        "conscientiousness_boost": 0.1,
    },
    Mood.CURIOUS: {
        "rate_multiplier": 1.1,
        "gap_bias": 0.3,           # prefer unexplored territory
        "depth_bonus": 1,
    },
}


# Events that trigger mood changes
MOOD_TRIGGERS: dict[str, Mood] = {
    "critical_finding": Mood.EXCITED,
    "high_finding": Mood.EXCITED,
    "false_positive": Mood.CAUTIOUS,
    "blocked": Mood.FRUSTRATED,
    "rate_limited": Mood.FRUSTRATED,
    "mission_success": Mood.SATISFIED,
    "mission_failed": Mood.FRUSTRATED,
    "50_targets_nothing": Mood.BORED,
    "novel_discovery": Mood.CURIOUS,
    "start_mission": Mood.CURIOUS,
}


def set_mood(mood: Mood, reason: str = "") -> dict[str, Any]:
    """Set the current mood with expiry timer."""
    duration = MOOD_DURATIONS.get(mood, 0)
    expires = (datetime.now() + timedelta(minutes=duration)).isoformat() if duration > 0 else None

    state = _load_state()
    state.mood = mood.value
    state.mood_expires = expires if expires else None
    _save_state(state)

    MOOD_FILE.parent.mkdir(parents=True, exist_ok=True)
    MOOD_FILE.write_text(json.dumps({
        "mood": mood.value,
        "expires": expires,
        "reason": reason,
        "set_at": datetime.now().isoformat(),
        "effects": MOOD_EFFECTS.get(mood, {}),
    }, indent=2))

    logger.info(f"Mood set to {mood.value} ({reason}) — expires at {expires or 'never'}")

    return {
        "mood": mood.value,
        "expires": expires,
        "reason": reason,
        "effects": MOOD_EFFECTS.get(mood, {}),
    }


def get_current_mood() -> dict[str, Any]:
    """Get current mood, checking for expiry."""
    state = _load_state()
    mood_str = state.mood
    expires = state.mood_expires

    # Check if mood has expired
    if expires:
        try:
            exp_time = datetime.fromisoformat(expires)
            if datetime.now() > exp_time:
                # Mood expired — revert to neutral
                return set_mood(Mood.NEUTRAL, "Previous mood expired")
        except (ValueError, TypeError):
            pass

    mood = Mood(mood_str) if mood_str in [m.value for m in Mood] else Mood.NEUTRAL
    effects = MOOD_EFFECTS.get(mood, {})

    return {
        "mood": mood.value,
        "expires": expires,
        "effects": effects,
    }


def trigger_mood(event: str, reason: str = "") -> dict[str, Any]:
    """Trigger a mood change based on an event."""
    mood = MOOD_TRIGGERS.get(event)
    if not mood:
        return get_current_mood()

    return set_mood(mood, reason or f"Triggered by event: {event}")


def get_mood_effects() -> dict[str, float]:
    """Get the current mood's effects on exploration parameters."""
    mood_data = get_current_mood()
    return mood_data.get("effects", {})