"""PITBULL Mistake Learning System — learns from false positives, missed findings, and errors.

Every mistake is logged with:
- What was the situation?
- What did PITBULL do?
- What should it have done?
- What trait adjustment would prevent this?

Academic basis:
- Pentest-R1 (arXiv:2508.07382): RL reward — false positive = penalty, novel discovery = bonus
- CurriculumPT (MDPI 2025): graduated learning from mistakes
- Galaxy (arXiv:2508.03991): proactive self-improvement
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import settings
from app.core.database import cypher_write, cypher_read
from app.core.evolution import apply_event

logger = logging.getLogger(__name__)

MISTAKE_FILE = Path(settings.state_dir) / "mistakes.jsonl"


class Mistake:
    """A logged mistake with lesson extraction."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class MistakeLearner:
    """Logs and learns from exploration mistakes."""

    def log_mistake(
        self,
        mistake_type: str,
        target: str,
        situation: str,
        what_pitbull_did: str,
        what_should_have_done: str,
        lesson: str,
        trait_suggestion: str = "",
        severity: str = "medium",
    ) -> dict[str, Any]:
        """Log a mistake and extract lessons."""
        mistake_id = str(uuid.uuid4())[:12]
        timestamp = datetime.now().isoformat()

        mistake_data = {
            "id": mistake_id,
            "mistake_type": mistake_type,
            "target": target,
            "situation": situation,
            "what_pitbull_did": what_pitbull_did,
            "what_should_have_done": what_should_have_done,
            "lesson": lesson,
            "trait_suggestion": trait_suggestion,
            "severity": severity,
            "timestamp": timestamp,
        }

        # Write to file
        MISTAKE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(MISTAKE_FILE, "a") as f:
            f.write(json.dumps(mistake_data) + "\n")

        # Store in Neo4j as procedural memory
        cypher_write(
            "CREATE (m:Memory {id: $id}) "
            "SET m.memory_type = 'procedural', m.content = $content, "
            "m.target = $target, m.severity = $severity, m.timestamp = datetime(), "
            "m.mistake_type = $mtype, m.lesson = $lesson",
            {
                "id": mistake_id,
                "content": f"MISTAKE [{mistake_type}]: {situation} → did: {what_pitbull_did} → should: {what_should_have_done} → lesson: {lesson}",
                "target": target,
                "severity": severity,
                "mtype": mistake_type,
                "lesson": lesson,
            },
        )

        # Apply personality evolution based on mistake type
        evolution_map = {
            "false_positive": ("false_positive", target, f"False positive: {lesson}"),
            "missed_finding": ("missed_finding_rushed", target, f"Missed finding: {lesson}"),
            "blocked": ("blocked_aggressive", target, f"Got blocked: {lesson}"),
            "timeout": ("rate_limited", target, f"Timeout: {lesson}"),
            "misclassification": ("false_positive", target, f"Misclassification: {lesson}"),
        }
        if mistake_type in evolution_map:
            apply_event(*evolution_map[mistake_type])

        logger.info(f"Mistake logged: [{mistake_type}] {target} — lesson: {lesson[:80]}")
        return mistake_data

    def get_mistakes(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent mistakes from file."""
        if not MISTAKE_FILE.exists():
            return []
        mistakes = []
        with open(MISTAKE_FILE, "r") as f:
            for line in f:
                try:
                    mistakes.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return mistakes[-limit:]

    def get_lessons(self) -> list[dict[str, Any]]:
        """Get all unique lessons learned."""
        mistakes = self.get_mistakes(200)
        # Also check Neo4j for procedural memories with lessons
        db_lessons = cypher_read(
            "MATCH (m:Memory {memory_type: 'procedural'}) "
            "WHERE m.lesson IS NOT NULL "
            "RETURN m.lesson AS lesson, m.mistake_type AS type, m.target AS target, m.timestamp AS ts "
            "ORDER BY m.timestamp DESC LIMIT 100",
        )

        lessons: dict[str, dict] = {}
        for m in mistakes:
            key = m.get("lesson", "")
            if key and key not in lessons:
                lessons[key] = {
                    "lesson": key,
                    "type": m.get("mistake_type", ""),
                    "target": m.get("target", ""),
                    "timestamp": m.get("timestamp", ""),
                    "source": "file",
                }

        for row in db_lessons:
            lesson_text = row.get("lesson", "")
            if lesson_text and lesson_text not in lessons:
                lessons[lesson_text] = {
                    "lesson": lesson_text,
                    "type": row.get("type", ""),
                    "target": row.get("target", ""),
                    "timestamp": str(row.get("ts", "")),
                    "source": "database",
                }

        return list(lessons.values())

    def get_mistake_stats(self) -> dict[str, Any]:
        """Get statistics about mistakes."""
        mistakes = self.get_mistakes(500)
        type_counts: dict[str, int] = {}
        for m in mistakes:
            mtype = m.get("mistake_type", "unknown")
            type_counts[mtype] = type_counts.get(mtype, 0) + 1

        return {
            "total_mistakes": len(mistakes),
            "by_type": type_counts,
            "unique_lessons": len(self.get_lessons()),
        }

    def check_past_mistakes(self, target: str, situation: str) -> list[dict[str, Any]]:
        """Check if current situation resembles a past mistake."""
        mistakes = self.get_mistakes(100)
        relevant = []
        situation_lower = situation.lower()
        for m in mistakes:
            # Simple text similarity — check for shared keywords
            past_situation = m.get("situation", "").lower()
            if target.lower() in past_situation or any(
                word in past_situation for word in situation_lower.split() if len(word) > 4
            ):
                relevant.append(m)
        return relevant[:5]


mistake_learner = MistakeLearner()