"""PITBULL Opinion System — evidence-backed opinions with confidence.

PITBULL develops opinions about technology, patterns, and infrastructure.
Opinions are stored in Neo4j and revised when new evidence contradicts them.

Academic basis:
- PersonaAgent (ACL 2026): personality shapes opinions
- Memory Beyond Recall (arXiv:2606.09483): semantic memory as generalized knowledge
- Galaxy (arXiv:2508.03991): proactive knowledge expansion
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)


class OpinionSystem:
    """Manages PITBULL's opinions about the digital world."""

    def form_opinion(
        self,
        subject: str,
        opinion_text: str,
        evidence: str,
        confidence: float = 0.5,
        category: str = "general",
    ) -> dict[str, Any]:
        """Form a new opinion or update an existing one."""
        op_id = str(uuid.uuid4())[:12]

        # Check if opinion about this subject already exists
        existing = cypher_read(
            "MATCH (o:Opinion {subject: $subject}) RETURN o",
            {"subject": subject},
        )

        if existing:
            # Update existing opinion with new evidence
            old = existing[0]["o"]
            old_confidence = old.get("confidence", 0.5)
            old_evidence_count = old.get("evidence_count", 0)

            # Bayesian-ish update: weight new evidence with old
            new_confidence = (old_confidence * old_evidence_count + confidence) / (old_evidence_count + 1)
            new_evidence_count = old_evidence_count + 1

            # Check if new evidence contradicts old opinion
            contradicts = self._check_contradiction(old.get("text", ""), opinion_text)

            if contradicts:
                # Reduce confidence and note the contradiction
                new_confidence *= 0.7
                cypher_write(
                    "MATCH (o:Opinion {subject: $subject}) "
                    "SET o.text = $text, o.confidence = $conf, "
                    "o.evidence_count = $count, o.last_updated = datetime(), "
                    "o.last_evidence = $evidence, o.contradictions = o.contradictions + 1, "
                    "o.revised = true",
                    {
                        "subject": subject,
                        "text": opinion_text,
                        "conf": round(new_confidence, 4),
                        "count": new_evidence_count,
                        "evidence": evidence,
                    },
                )
                logger.info(f"Opinion on '{subject}' REVISED due to contradiction — confidence {new_confidence:.2f}")
            else:
                # Supporting evidence
                cypher_write(
                    "MATCH (o:Opinion {subject: $subject}) "
                    "SET o.text = $text, o.confidence = $conf, "
                    "o.evidence_count = $count, o.last_updated = datetime(), "
                    "o.last_evidence = $evidence, o.supporting_count = o.supporting_count + 1",
                    {
                        "subject": subject,
                        "text": opinion_text,
                        "conf": round(new_confidence, 4),
                        "count": new_evidence_count,
                        "evidence": evidence,
                    },
                )
                logger.info(f"Opinion on '{subject}' reinforced — confidence {new_confidence:.2f}")

            return {
                "subject": subject,
                "text": opinion_text,
                "confidence": round(new_confidence, 4),
                "evidence_count": new_evidence_count,
                "revised": contradicts,
            }
        else:
            # Create new opinion
            cypher_write(
                "CREATE (o:Opinion {id: $id}) "
                "SET o.subject = $subject, o.text = $text, o.confidence = $conf, "
                "o.evidence_count = 1, o.supporting_count = 1, o.contradictions = 0, "
                "o.category = $category, o.first_formed = datetime(), "
                "o.last_updated = datetime(), o.last_evidence = $evidence, o.revised = false",
                {
                    "id": op_id,
                    "subject": subject,
                    "text": opinion_text,
                    "conf": round(confidence, 4),
                    "category": category,
                    "evidence": evidence,
                },
            )
            logger.info(f"New opinion formed: '{subject}' — {opinion_text[:80]}... (conf={confidence:.2f})")

            return {
                "subject": subject,
                "text": opinion_text,
                "confidence": round(confidence, 4),
                "evidence_count": 1,
                "revised": False,
            }

    def get_opinions(self, category: str | None = None, min_confidence: float = 0.0) -> list[dict[str, Any]]:
        """Get all opinions, optionally filtered."""
        if category:
            results = cypher_read(
                "MATCH (o:Opinion {category: $cat}) "
                "WHERE o.confidence >= $min_conf "
                "RETURN o ORDER BY o.confidence DESC",
                {"cat": category, "min_conf": min_confidence},
            )
        else:
            results = cypher_read(
                "MATCH (o:Opinion) WHERE o.confidence >= $min_conf "
                "RETURN o ORDER BY o.confidence DESC",
                {"min_conf": min_confidence},
            )

        opinions = []
        for row in results:
            o = row.get("o", {})
            opinions.append({
                "id": o.get("id", ""),
                "subject": o.get("subject", ""),
                "text": o.get("text", ""),
                "confidence": o.get("confidence", 0),
                "evidence_count": o.get("evidence_count", 0),
                "supporting_count": o.get("supporting_count", 0),
                "contradictions": o.get("contradictions", 0),
                "category": o.get("category", "general"),
                "revised": o.get("revised", False),
                "first_formed": str(o.get("first_formed", "")),
                "last_updated": str(o.get("last_updated", "")),
            })

        return opinions

    def get_opinion(self, subject: str) -> dict[str, Any] | None:
        """Get a specific opinion by subject."""
        results = cypher_read(
            "MATCH (o:Opinion {subject: $subject}) RETURN o",
            {"subject": subject},
        )
        if not results:
            return None
        o = results[0].get("o", {})
        return {
            "subject": o.get("subject", ""),
            "text": o.get("text", ""),
            "confidence": o.get("confidence", 0),
            "evidence_count": o.get("evidence_count", 0),
            "category": o.get("category", "general"),
        }

    def _check_contradiction(self, old_text: str, new_text: str) -> bool:
        """Simple heuristic contradiction check."""
        # Check for negation patterns
        negation_words = ["not", "never", "rarely", "unlikely", "false", "incorrect", "wrong"]
        old_lower = old_text.lower()
        new_lower = new_text.lower()

        # If old says "often" and new says "rarely" → contradiction
        if "often" in old_lower and any(neg in new_lower for neg in negation_words):
            return True
        if "always" in old_lower and "never" in new_lower:
            return True
        if "vulnerable" in old_lower and "secure" in new_lower:
            return True
        if "secure" in old_lower and "vulnerable" in new_lower:
            return True
        if "safe" in old_lower and "dangerous" in new_lower:
            return True

        return False

    def generate_opinion_from_findings(
        self,
        target: str,
        findings: list[dict[str, Any]],
        llm_callback=None,
    ) -> dict[str, Any] | None:
        """Use LLM to generate an opinion from exploration findings."""
        if not findings:
            return None

        # Simple pattern-based opinion generation (no LLM required)
        tech_counts: dict[str, int] = {}
        vuln_counts: dict[str, int] = {}

        for f in findings:
            for tech in f.get("tech_hints", []):
                tech_counts[tech] = tech_counts.get(tech, 0) + 1
            if f.get("interesting_paths"):
                vuln_counts["exposed_paths"] = vuln_counts.get("exposed_paths", 0) + 1

        # Form opinions about technologies
        opinions_formed = []
        for tech, count in tech_counts.items():
            if count >= 3:
                opinion = self.form_opinion(
                    subject=f"technology:{tech}",
                    opinion_text=f"{tech} is commonly encountered ({count} times in recent explorations)",
                    evidence=f"Found {tech} on {target} and {count-1} other targets",
                    confidence=min(0.9, 0.3 + count * 0.1),
                    category="technology",
                )
                opinions_formed.append(opinion)

        if vuln_counts.get("exposed_paths", 0) >= 2:
            opinion = self.form_opinion(
                subject=f"security:{target}",
                opinion_text=f"{target} has multiple exposed paths — may have configuration issues",
                evidence=f"Found {vuln_counts['exposed_paths']} exposed paths during exploration",
                confidence=0.6,
                category="security",
            )
            opinions_formed.append(opinion)

        return {"opinions_formed": opinions_formed} if opinions_formed else None


# Singleton
opinion_system = OpinionSystem()