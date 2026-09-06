"""PITBULL Personality Drift — gradual trait evolution over time.

Traits slowly drift based on the balance of experiences:
- Many successful missions → slight confidence increase (neuroticism drift down)
- Many novel findings → openness drift up
- Many blocked attempts → extraversion drift down, neuroticism up
- Long periods without exploration → slight neuroticism increase (anxiety)

Academic basis:
- PersonaAgent (ACL 2026): personality-memory feedback loop
- Personality-Driven Decision-Making (arXiv:2504.00727): trait evolution over time
- Galaxy (arXiv:2508.03991): self-evolving agent with drift
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from app.api.personality import _load_state, _save_state
from app.core.evolution import get_history, apply_adjustment, TraitAdjustment
from app.core.database import cypher_read

logger = logging.getLogger(__name__)


class PersonalityDrift:
    """Manages gradual personality drift based on accumulated experience."""

    # Drift rates per week (very small)
    DRIFT_RATES = {
        # Trait: (positive_drift, negative_drift) per week
        "openness": (0.005, -0.003),       # Novel findings → up, routine → down
        "conscientiousness": (0.004, -0.002),  # Mistakes → up, success → down (complacent)
        "extraversion": (0.003, -0.004),    # Success → up, blocks → down
        "agreeableness": (0.002, -0.002),   # Balanced — stays relatively stable
        "neuroticism": (-0.003, 0.004),     # Success → down, failures → up
    }

    def calculate_drift(self, days: int = 7) -> dict[str, Any]:
        """Calculate personality drift based on recent experience balance."""
        state = _load_state()
        history = get_history(200)

        # Count events in the time window
        cutoff = datetime.now() - timedelta(days=days)
        recent_events: list[dict] = []
        for entry in history:
            try:
                ts = datetime.fromisoformat(entry.get("timestamp", ""))
                if ts > cutoff:
                    recent_events.append(entry)
            except (ValueError, TypeError):
                continue

        # Calculate experience balance
        positive_events = sum(1 for e in recent_events if e.get("delta", 0) > 0)
        negative_events = sum(1 for e in recent_events if e.get("delta", 0) < 0)
        total_events = len(recent_events)

        # Mission success ratio
        missions = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.content CONTAINS 'Mission complete' "
            "RETURN count(m) AS success_count",
        )
        failed = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.content CONTAINS 'Mission failed' "
            "RETURN count(m) AS fail_count",
        )

        success_count = missions[0]["success_count"] if missions else 0
        fail_count = failed[0]["fail_count"] if failed else 0
        total_missions = success_count + fail_count

        # Calculate drift for each trait
        drift_adjustments: list[dict[str, Any]] = []

        for trait, (pos_rate, neg_rate) in self.DRIFT_RATES.items():
            # Weekly drift scaled by days
            scale = days / 7.0

            if total_events > 0:
                positive_ratio = positive_events / total_events
                negative_ratio = negative_events / total_events
            else:
                positive_ratio = negative_ratio = 0

            # Base drift from event balance
            drift = (pos_rate * positive_ratio - neg_rate * negative_ratio) * scale

            # Mission success influence
            if total_missions > 0:
                success_ratio = success_count / total_missions
                if trait == "neuroticism":
                    drift -= 0.002 * success_ratio * scale  # success → less anxious
                elif trait == "openness":
                    drift += 0.002 * success_ratio * scale  # success → more open
                elif trait == "conscientiousness":
                    drift -= 0.001 * success_ratio * scale  # success → slightly complacent

            # Inactivity drift (no recent events)
            if total_events == 0:
                if trait == "neuroticism":
                    drift += 0.001 * scale  # anxiety from inactivity
                elif trait == "openness":
                    drift -= 0.001 * scale  # slight curiosity decrease

            # Apply drift (very small, clamped)
            drift = max(-0.02, min(0.02, drift))  # cap per drift cycle

            if abs(drift) > 0.0001:
                current_val = getattr(state, trait, 0.5)
                # Only drift if not at extremes
                if 0.1 < current_val < 0.9:
                    adjustment = TraitAdjustment(
                        trait=trait,
                        delta=round(drift, 5),
                        reason=f"Personality drift ({days}d): {positive_events} positive, {negative_events} negative events, {success_count}/{total_missions} mission success",
                        event_type="drift",
                    )
                    result = apply_adjustment(adjustment)
                    drift_adjustments.append(result)

        return {
            "days_analyzed": days,
            "total_events": total_events,
            "positive_events": positive_events,
            "negative_events": negative_events,
            "mission_success_rate": success_count / total_missions if total_missions > 0 else 0,
            "total_missions": total_missions,
            "drift_adjustments": drift_adjustments,
            "drift_count": len(drift_adjustments),
        }

    def get_drift_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get personality drift history."""
        history = get_history(limit * 3)  # get more to filter
        drift_entries = [e for e in history if e.get("event_type") == "drift"]
        return drift_entries[-limit:]


personality_drift = PersonalityDrift()