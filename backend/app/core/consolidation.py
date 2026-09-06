"""PITBULL Memory Consolidation — episodic → semantic distillation.

Runs between missions. Collects episodic memories, identifies patterns,
and creates/updates semantic rules. Old episodic memories are compressed.

Academic basis:
- Memory Beyond Recall (arXiv:2606.09483): dual-process memory consolidation
- SYNAPSE (ACL 2026): spreading activation in memory graph
- TiMem (ACL 2026): temporal-hierarchical consolidation
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)


class MemoryConsolidator:
    """Consolidates episodic memories into semantic rules."""

    def consolidate(self, since_hours: int = 24) -> dict[str, Any]:
        """Run consolidation cycle on recent episodic memories."""
        results = {
            "episodic_collected": 0,
            "patterns_found": 0,
            "semantic_rules_created": 0,
            "semantic_rules_updated": 0,
            "episodic_compressed": 0,
            "patterns": [],
        }

        # 1. Collect recent episodic memories
        episodic = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.timestamp >= datetime() - duration({hours: $hours}) "
            "RETURN m ORDER BY m.timestamp DESC",
            {"hours": since_hours},
        )
        results["episodic_collected"] = len(episodic)

        if len(episodic) < 5:
            logger.info(f"Not enough episodic memories for consolidation ({len(episodic)} < 5)")
            return results

        # 2. Pattern detection — technology patterns
        tech_patterns = self._detect_tech_patterns(episodic)
        for pattern in tech_patterns:
            rule = self._upsert_semantic_rule(
                rule_type="technology_pattern",
                subject=pattern["subject"],
                content=pattern["content"],
                evidence_count=pattern["evidence_count"],
                confidence=pattern["confidence"],
                source_memories=pattern["source_ids"],
            )
            if rule["created"]:
                results["semantic_rules_created"] += 1
            else:
                results["semantic_rules_updated"] += 1
            results["patterns"].append(pattern)
            results["patterns_found"] += 1

        # 3. Pattern detection — security patterns
        security_patterns = self._detect_security_patterns(episodic)
        for pattern in security_patterns:
            rule = self._upsert_semantic_rule(
                rule_type="security_pattern",
                subject=pattern["subject"],
                content=pattern["content"],
                evidence_count=pattern["evidence_count"],
                confidence=pattern["confidence"],
                source_memories=pattern["source_ids"],
            )
            if rule["created"]:
                results["semantic_rules_created"] += 1
            else:
                results["semantic_rules_updated"] += 1
            results["patterns"].append(pattern)
            results["patterns_found"] += 1

        # 4. Pattern detection — infrastructure patterns
        infra_patterns = self._detect_infra_patterns(episodic)
        for pattern in infra_patterns:
            rule = self._upsert_semantic_rule(
                rule_type="infrastructure_pattern",
                subject=pattern["subject"],
                content=pattern["content"],
                evidence_count=pattern["evidence_count"],
                confidence=pattern["confidence"],
                source_memories=pattern["source_ids"],
            )
            if rule["created"]:
                results["semantic_rules_created"] += 1
            else:
                results["semantic_rules_updated"] += 1
            results["patterns"].append(pattern)
            results["patterns_found"] += 1

        # 5. Compress old episodic memories
        compressed = self._compress_old_episodic(days_old=7)
        results["episodic_compressed"] = compressed

        logger.info(
            f"Consolidation complete: {results['episodic_collected']} episodic → "
            f"{results['patterns_found']} patterns → "
            f"{results['semantic_rules_created']} new + {results['semantic_rules_updated']} updated rules, "
            f"{compressed} episodic compressed"
        )

        return results

    def _detect_tech_patterns(self, episodic: list[dict]) -> list[dict]:
        """Detect technology patterns from episodic memories."""
        patterns: dict[str, dict] = {}

        for entry in episodic:
            m = entry.get("m", {})
            content = m.get("content", "").lower()

            # Extract technology mentions
            techs = self._extract_techs(content)
            for tech in techs:
                if tech not in patterns:
                    patterns[tech] = {
                        "subject": f"tech:{tech}",
                        "content": f"Technology {tech} encountered in explorations",
                        "evidence_count": 0,
                        "confidence": 0.0,
                        "source_ids": [],
                    }
                patterns[tech]["evidence_count"] += 1
                patterns[tech]["source_ids"].append(m.get("id", ""))

        # Only keep patterns with 3+ occurrences
        result = []
        for p in patterns.values():
            if p["evidence_count"] >= 3:
                p["confidence"] = min(0.9, 0.3 + p["evidence_count"] * 0.1)
                result.append(p)

        return result

    def _detect_security_patterns(self, episodic: list[dict]) -> list[dict]:
        """Detect security-relevant patterns."""
        patterns: dict[str, dict] = {}
        security_keywords = [
            "admin", "login", ".git", ".env", "config", "backup", "debug",
            "swagger", "graphql", "api", "dashboard", "console",
        ]

        for entry in episodic:
            m = entry.get("m", {})
            content = m.get("content", "").lower()

            for kw in security_keywords:
                if kw in content:
                    if kw not in patterns:
                        patterns[kw] = {
                            "subject": f"security:{kw}",
                            "content": f"'{kw}' endpoint found across multiple targets — common exposure pattern",
                            "evidence_count": 0,
                            "confidence": 0.0,
                            "source_ids": [],
                        }
                    patterns[kw]["evidence_count"] += 1
                    patterns[kw]["source_ids"].append(m.get("id", ""))

        result = []
        for p in patterns.values():
            if p["evidence_count"] >= 2:
                p["confidence"] = min(0.85, 0.25 + p["evidence_count"] * 0.15)
                result.append(p)

        return result

    def _detect_infra_patterns(self, episodic: list[dict]) -> list[dict]:
        """Detect infrastructure patterns (CDNs, hosting, DNS)."""
        patterns: dict[str, dict] = {}

        for entry in episodic:
            m = entry.get("m", {})
            content = m.get("content", "").lower()

            # Detect CDN/hosting patterns
            cdns = ["cloudflare", "akamai", "fastly", "cloudfront", "incapsula"]
            for cdn in cdns:
                if cdn in content:
                    if cdn not in patterns:
                        patterns[cdn] = {
                            "subject": f"infra:{cdn}",
                            "content": f"{cdn} CDN detected — affects exploration strategy (WAF, rate limits)",
                            "evidence_count": 0,
                            "confidence": 0.0,
                            "source_ids": [],
                        }
                    patterns[cdn]["evidence_count"] += 1
                    patterns[cdn]["source_ids"].append(m.get("id", ""))

        result = []
        for p in patterns.values():
            if p["evidence_count"] >= 2:
                p["confidence"] = min(0.9, 0.4 + p["evidence_count"] * 0.1)
                result.append(p)

        return result

    def _extract_techs(self, content: str) -> list[str]:
        """Extract technology names from memory content."""
        known_techs = [
            "nginx", "apache", "cloudflare", "wordpress", "php", "asp.net",
            "express", "react", "vue", "angular", "jquery", "bootstrap",
            "tailwind", "next.js", "jenkins", "grafana", "kibana",
            "docker", "kubernetes", "nginx", "tomcat", "node",
        ]
        found = []
        for tech in known_techs:
            if tech in content:
                found.append(tech)
        return found

    def _upsert_semantic_rule(
        self,
        rule_type: str,
        subject: str,
        content: str,
        evidence_count: int,
        confidence: float,
        source_memories: list[str],
    ) -> dict[str, Any]:
        """Create or update a semantic memory rule."""
        # Check if rule exists
        existing = cypher_read(
            "MATCH (m:Memory {memory_type: 'semantic', subject: $subject}) RETURN m",
            {"subject": subject},
        )

        if existing:
            # Update
            old = existing[0].get("m", {})
            old_count = old.get("evidence_count", 0)
            new_count = old_count + evidence_count
            new_confidence = min(0.95, (old.get("confidence", 0.5) * old_count + confidence * evidence_count) / new_count)

            cypher_write(
                "MATCH (m:Memory {memory_type: 'semantic', subject: $subject}) "
                "SET m.content = $content, m.confidence = $conf, "
                "m.evidence_count = $count, m.last_updated = datetime(), "
                "m.times_applied = m.times_applied",
                {
                    "subject": subject,
                    "content": content,
                    "conf": round(new_confidence, 4),
                    "count": new_count,
                },
            )
            return {"created": False, "subject": subject, "confidence": new_confidence}
        else:
            # Create
            rule_id = str(uuid.uuid4())[:12]
            cypher_write(
                "CREATE (m:Memory {id: $id}) "
                "SET m.memory_type = 'semantic', m.subject = $subject, "
                "m.content = $content, m.confidence = $conf, "
                "m.evidence_count = $count, m.rule_type = $rule_type, "
                "m.times_applied = 0, m.times_confirmed = 0, m.times_refuted = 0, "
                "m.first_formed = datetime(), m.last_updated = datetime()",
                {
                    "id": rule_id,
                    "subject": subject,
                    "content": content,
                    "conf": round(confidence, 4),
                    "count": evidence_count,
                    "rule_type": rule_type,
                },
            )
            return {"created": True, "subject": subject, "confidence": confidence}

    def _compress_old_episodic(self, days_old: int = 7) -> int:
        """Compress episodic memories older than N days into summaries."""
        # Mark old memories as compressed
        result = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.timestamp < datetime() - duration({days: $days}) "
            "AND NOT m.compressed = true "
            "RETURN count(m) AS count",
            {"days": days_old},
        )

        count = result[0]["count"] if result else 0
        if count == 0:
            return 0

        # Compress: keep summary, mark as compressed
        cypher_write(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.timestamp < datetime() - duration({days: $days}) "
            "AND NOT m.compressed = true "
            "SET m.compressed = true, m.content = 'COMPRESSED: ' + substring(m.content, 0, 100)",
            {"days": days_old},
        )

        return count

    def get_semantic_rules(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get all semantic rules."""
        results = cypher_read(
            "MATCH (m:Memory {memory_type: 'semantic'}) "
            "RETURN m ORDER BY m.confidence DESC LIMIT $limit",
            {"limit": limit},
        )

        rules = []
        for row in results:
            m = row.get("m", {})
            rules.append({
                "id": m.get("id", ""),
                "subject": m.get("subject", ""),
                "content": m.get("content", ""),
                "rule_type": m.get("rule_type", ""),
                "confidence": m.get("confidence", 0),
                "evidence_count": m.get("evidence_count", 0),
                "times_applied": m.get("times_applied", 0),
                "times_confirmed": m.get("times_confirmed", 0),
                "times_refuted": m.get("times_refuted", 0),
                "last_updated": str(m.get("last_updated", "")),
            })

        return rules


# Singleton
memory_consolidator = MemoryConsolidator()