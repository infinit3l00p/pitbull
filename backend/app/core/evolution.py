"""PITBULL Personality Evolution — OCEAN traits evolve through experience.

Trait adjustments are logged with triggering events for auditability.

Academic basis:
- PersonaAgent (ACL 2026): personality-memory feedback loop
- Personality-Driven Decision-Making (arXiv:2504.00727): OCEAN in LLM agents
- Galaxy (arXiv:2508.03991): self-evolving agent framework
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from app.config import settings
from app.api.personality import _load_state, _save_state, STATE_FILE

logger = logging.getLogger(__name__)

# Evolution history file
HISTORY_FILE = Path(settings.state_dir) / "personality_history.jsonl"


@dataclass
class TraitAdjustment:
    """A single trait adjustment event."""
    trait: str
    delta: float
    reason: str
    event_type: str  # finding, false_positive, blocked, mistake, success, study
    target: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "trait": self.trait,
            "delta": self.delta,
            "reason": self.reason,
            "event_type": self.event_type,
            "target": self.target,
            "timestamp": self.timestamp,
        }


# ── Evolution Rules ────────────────────────────────────────────────
# Each rule defines: event_type → trait adjustments
EVOLUTION_RULES: dict[str, dict[str, float]] = {
    # Found something critical by being creative
    "critical_finding_creative": {
        "openness": +0.02,
        "neuroticism": -0.01,
    },
    # Found something by thorough checking
    "critical_finding_thorough": {
        "conscientiousness": +0.02,
        "neuroticism": -0.01,
    },
    # Missed a finding by rushing
    "missed_finding_rushed": {
        "conscientiousness": +0.03,
        "extraversion": -0.01,
    },
    # Got blocked/banned by being too aggressive
    "blocked_aggressive": {
        "extraversion": -0.05,
        "neuroticism": +0.02,
        "agreeableness": +0.02,
    },
    # False positive reported
    "false_positive": {
        "neuroticism": +0.02,
        "conscientiousness": +0.01,
    },
    # True positive confirmed
    "true_positive": {
        "neuroticism": -0.01,
        "openness": +0.01,
    },
    # Successfully explored unusual path
    "novel_approach_success": {
        "openness": +0.02,
    },
    # Failed with novel approach
    "novel_approach_failed": {
        "openness": -0.01,
        "neuroticism": +0.01,
    },
    # Completed a successful mission
    "mission_success": {
        "neuroticism": -0.005,
    },
    # Mission failed
    "mission_failed": {
        "neuroticism": +0.01,
    },
    # Studied new knowledge between missions
    "knowledge_expansion": {
        "openness": +0.01,
        "conscientiousness": +0.01,
    },
    # Got rate-limited
    "rate_limited": {
        "extraversion": -0.02,
        "agreeableness": +0.01,
    },
}


def apply_adjustment(adjustment: TraitAdjustment) -> dict[str, Any]:
    """Apply a trait adjustment to the personality state."""
    state = _load_state()

    # Clamp trait to [0.05, 0.95] — never fully extreme
    current = getattr(state, adjustment.trait, 0.5)
    new_val = max(0.05, min(0.95, current + adjustment.delta))
    setattr(state, adjustment.trait, round(new_val, 4))

    _save_state(state)

    # Log to history
    _log_history(adjustment)

    logger.info(
        f"Personality evolved: {adjustment.trait} {current:.4f} → {new_val:.4f} "
        f"({adjustment.delta:+.4f}) — {adjustment.reason}"
    )

    return {
        "trait": adjustment.trait,
        "old_value": round(current, 4),
        "new_value": round(new_val, 4),
        "delta": adjustment.delta,
        "reason": adjustment.reason,
        "event_type": adjustment.event_type,
    }


def apply_event(event_type: str, target: str = "", reason: str = "") -> list[dict[str, Any]]:
    """Apply all trait adjustments for an event type."""
    rules = EVOLUTION_RULES.get(event_type, {})
    if not rules:
        logger.warning(f"No evolution rules for event type: {event_type}")
        return []

    results = []
    for trait, delta in rules.items():
        adj = TraitAdjustment(
            trait=trait,
            delta=delta,
            reason=reason or f"Event: {event_type}",
            event_type=event_type,
            target=target,
        )
        results.append(apply_adjustment(adj))

    return results


def _log_history(adjustment: TraitAdjustment) -> None:
    """Append adjustment to history file."""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_FILE, "a") as f:
        f.write(json.dumps(adjustment.to_dict()) + "\n")


def get_history(limit: int = 50) -> list[dict[str, Any]]:
    """Read personality evolution history."""
    if not HISTORY_FILE.exists():
        return []

    entries = []
    with open(HISTORY_FILE, "r") as f:
        for line in f:
            try:
                entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue

    return entries[-limit:]


def get_evolution_summary() -> dict[str, Any]:
    """Get a summary of personality evolution."""
    history = get_history(200)

    trait_totals: dict[str, float] = {}
    event_counts: dict[str, int] = {}

    for entry in history:
        trait = entry.get("trait", "")
        delta = entry.get("delta", 0)
        event_type = entry.get("event_type", "")

        trait_totals[trait] = trait_totals.get(trait, 0) + delta
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    return {
        "total_adjustments": len(history),
        "trait_deltas": trait_totals,
        "event_counts": event_counts,
        "history": history[-20:],  # last 20 for display
    }