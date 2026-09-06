"""PITBULL Curiosity Engine — drives autonomous exploration.

Scores potential targets on a 0-100 curiosity scale based on:
- Novelty (0-30): How different from what PITBULL has seen before
- Anomaly (0-25): Deviation from expected patterns
- Gap (0-20): Unexplored territory nearby
- Potential Impact (0-15): How valuable findings could be
- Personality Weight (0-10): OCEAN traits modulate scoring

Academic basis:
- WebExplorer (arXiv:2509.06501): exploration-exploitation tradeoff for long-horizon agents
- PersonaAgent (ACL 2026): personality shapes what the agent notices
- Galaxy (arXiv:2508.03991): proactive knowledge gap identification
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.core.database import cypher_read, cypher_write
from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class CuriosityScore:
    """Curiosity score breakdown for a target."""
    target: str
    total: int
    novelty: int
    anomaly: int
    gap: int
    impact: int
    personality_weight: int
    reason: str
    priority: str  # high, medium, low
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total": self.total,
            "novelty": self.novelty,
            "anomaly": self.anomaly,
            "gap": self.gap,
            "impact": self.impact,
            "personality_weight": self.personality_weight,
            "reason": self.reason,
            "priority": self.priority,
            "timestamp": self.timestamp,
        }


class CuriosityEngine:
    """Scores targets by curiosity and maintains an exploration queue."""

    def __init__(self):
        self.threshold = 40  # minimum score to auto-queue
        self.max_queue_size = 100

    def _get_personality(self) -> dict[str, float]:
        """Load current personality traits."""
        from app.api.personality import _load_state
        try:
            state = _load_state()
            return {
                "openness": state.openness,
                "conscientiousness": state.conscientiousness,
                "extraversion": state.extraversion,
                "agreeableness": state.agreeableness,
                "neuroticism": state.neuroticism,
            }
        except Exception:
            return {
                "openness": settings.personality_openness,
                "conscientiousness": settings.personality_conscientiousness,
                "extraversion": settings.personality_extraversion,
                "agreeableness": settings.personality_agreeableness,
                "neuroticism": settings.personality_neuroticism,
            }

    def score_target(self, target: str, context: dict[str, Any] | None = None) -> CuriosityScore:
        """Score a single target's curiosity value."""
        context = context or {}
        personality = self._get_personality()

        # ── Novelty (0-30) ──────────────────────────────────────────
        novelty = self._score_novelty(target, context)
        # Personality modulates: high openness → novelty weighted higher
        novelty = int(novelty * (0.7 + 0.6 * personality["openness"]))

        # ── Anomaly (0-25) ──────────────────────────────────────────
        anomaly = self._score_anomaly(target, context)
        # High extraversion → anomaly weighted higher (active prober)
        anomaly = int(anomaly * (0.7 + 0.6 * personality["extraversion"]))

        # ── Gap (0-20) ──────────────────────────────────────────────
        gap = self._score_gap(target, context)
        # High conscientiousness → gaps weighted higher (thorough)
        gap = int(gap * (0.7 + 0.6 * personality["conscientiousness"]))

        # ── Potential Impact (0-15) ─────────────────────────────────
        impact = self._score_impact(target, context)

        # ── Personality Weight (0-10) ───────────────────────────────
        # High neuroticism → more cautious, slightly lower curiosity
        # High agreeableness → less aggressive, slightly lower curiosity
        pw = int(10 * (1.0 - personality["neuroticism"] * 0.3 - (1.0 - personality["agreeableness"]) * 0.2))

        total = min(100, novelty + anomaly + gap + impact + pw)
        priority = "high" if total >= 70 else "medium" if total >= self.threshold else "low"

        reason_parts = []
        if novelty >= 15: reason_parts.append(f"novel (n={novelty})")
        if anomaly >= 12: reason_parts.append(f"anomalous (a={anomaly})")
        if gap >= 10: reason_parts.append(f"unexplored gap (g={gap})")
        if impact >= 8: reason_parts.append(f"high-impact (i={impact})")
        reason = "; ".join(reason_parts) if reason_parts else f"low curiosity ({total})"

        return CuriosityScore(
            target=target,
            total=total,
            novelty=novelty,
            anomaly=anomaly,
            gap=gap,
            impact=impact,
            personality_weight=pw,
            reason=reason,
            priority=priority,
        )

    def _score_novelty(self, target: str, context: dict[str, Any]) -> int:
        """How different is this from what PITBULL has seen before?"""
        score = 0

        # Check if we've seen this target before
        seen = cypher_read(
            "MATCH (d:Domain {hostname: $target}) RETURN count(d) AS count",
            {"target": target},
        )
        if not seen or seen[0]["count"] == 0:
            score += 15  # Never seen this domain before

        # Check tech stack novelty
        tech_hints = context.get("tech_hints", [])
        if tech_hints:
            for tech in tech_hints:
                tech_seen = cypher_read(
                    "MATCH (m:Memory) WHERE m.content CONTAINS $tech "
                    "AND m.memory_type = 'episodic' RETURN count(m) AS count",
                    {"tech": tech},
                )
                count = tech_seen[0]["count"] if tech_seen else 0
                if count == 0:
                    score += 5  # Never seen this tech before
                elif count < 3:
                    score += 2  # Rarely seen

        # Check if target has unusual TLD
        tld = target.rsplit(".", 1)[-1].lower() if "." in target else ""
        unusual_tlds = {"onion", "i2p", "bit", "exit", "gg", "tk", "ml", "ga", "cf"}
        if tld in unusual_tlds:
            score += 10

        # Check for unusual ports
        ports = context.get("ports", [])
        common_ports = {80, 443, 22, 21, 25, 53, 8080, 8443}
        for port in ports:
            if port not in common_ports:
                score += 3

        return min(30, score)

    def _score_anomaly(self, target: str, context: dict[str, Any]) -> int:
        """Does this deviate from expected patterns?"""
        score = 0

        # Check for header anomalies
        headers = context.get("headers", {})
        server = headers.get("server", "").lower()

        # Mismatched or unusual server headers
        if server and "nginx" in server:
            version_match = cypher_read(
                "MATCH (m:Memory) WHERE m.content CONTAINS $server "
                "AND m.memory_type = 'episodic' RETURN count(m) AS count",
                {"server": server},
            )
            # Common server, low anomaly
            score += 1
        elif server and server not in ("", "nginx", "apache", "cloudflare", "envoy"):
            # Unusual server software
            score += 8

        # Check for certificate anomalies
        certs = context.get("certificates", [])
        for cert in certs:
            if cert.get("is_self_signed"):
                score += 5
            if cert.get("is_expired"):
                score += 5
            # Certificate covers different domain than target
            cert_domains = cert.get("all_domains", [])
            if cert_domains and target not in " ".join(cert_domains):
                score += 3

        # Check for DNS anomalies
        dns_records = context.get("dns_records", {})
        if dns_records.get("TXT"):
            txt_records = dns_records["TXT"]
            for txt in txt_records:
                if "v=spf1" not in txt and "google-site-verification" not in txt:
                    # Unusual TXT record
                    score += 2

        # Response code anomalies
        status_codes = context.get("status_codes", [])
        for code in status_codes:
            if code in (401, 403, 522, 523, 525, 526):
                score += 3  # Access denied or origin errors = interesting
            if code == 200 and "login" in str(context.get("urls", [])):
                score += 5  # Exposed login page

        return min(25, score)

    def _score_gap(self, target: str, context: dict[str, Any]) -> int:
        """Is there unexplored territory nearby?"""
        score = 0

        # Count subdomains vs explored subdomains
        sub_count = cypher_read(
            "MATCH (d:Domain {hostname: $target})-[:HAS_SUBDOMAIN]->(s:Subdomain) "
            "RETURN count(s) AS total",
            {"target": target},
        )
        total_subs = sub_count[0]["total"] if sub_count else 0

        if total_subs > 0:
            # Check how many subdomains have been resolved/crawled
            explored = cypher_read(
                "MATCH (d:Domain {hostname: $target})-[:HAS_SUBDOMAIN]->(s:Subdomain) "
                "WHERE s.last_seen IS NOT NULL "
                "AND EXISTS { MATCH (s)-[:RESOLVES_TO]->() } "
                "RETURN count(s) AS explored",
                {"target": target},
            )
            explored_count = explored[0]["explored"] if explored else 0
            unexplored = total_subs - explored_count
            if unexplored > 0:
                score += min(10, int(unexplored * 2))
        elif total_subs == 0:
            # No subdomains discovered yet — big gap
            score += 8

        # Check for IPs in same subnet that haven't been explored
        ips = context.get("ips", [])
        for ip in ips:
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = f"{'.'.join(parts[:3])}.0/24"
                subnet_count = cypher_read(
                    "MATCH (i:IPAddress) WHERE i.ip STARTS WITH $prefix "
                    "RETURN count(i) AS count",
                    {"prefix": ".".join(parts[:3]) + "."},
                )
                subnet_total = subnet_count[0]["count"] if subnet_count else 0
                if subnet_total < 5:
                    score += 5  # Sparse subnet — lots of unexplored IPs

        # Check for unexplored paths from crawl
        interesting_paths = context.get("interesting_paths", [])
        if interesting_paths:
            score += min(5, len(interesting_paths))

        return min(20, score)

    def _score_impact(self, target: str, context: dict[str, Any]) -> int:
        """How valuable could findings here be?"""
        score = 0

        # Check for admin/login endpoints
        urls = str(context.get("urls", []))
        paths = str(context.get("interesting_paths", []))
        if "admin" in urls.lower() or "admin" in paths.lower():
            score += 5
        if "api" in urls.lower() or "api" in paths.lower():
            score += 4
        if ".git" in paths.lower() or ".env" in paths.lower():
            score += 7  # High impact — exposed config
        if "graphql" in paths.lower():
            score += 5
        if "swagger" in paths.lower():
            score += 3

        # Check for forms (potential auth bypass, SQLi, XSS)
        forms = context.get("forms", [])
        if forms:
            score += min(4, len(forms))

        # Check target type — government/financial/health = higher impact
        tld = target.rsplit(".", 1)[-1].lower() if "." in target else ""
        if tld in ("gov", "mil"):
            score += 8
        elif tld in ("bank", "finance", "health"):
            score += 6
        elif tld in ("edu", "org"):
            score += 3

        # Tech stack with known vuln patterns
        tech_hints = context.get("tech_hints", [])
        tech_str = " ".join(tech_hints).lower()
        if "wordpress" in tech_str:
            score += 3  # Plugin ecosystem = attack surface
        if "php" in tech_str:
            score += 2
        if "jenkins" in tech_str or "grafana" in tech_str or "kibana" in tech_str:
            score += 6  # Exposed admin panels

        return min(15, score)

    def rank_targets(self, targets: list[str], context: dict[str, Any] | None = None) -> list[CuriosityScore]:
        """Rank multiple targets by curiosity score."""
        scores = []
        for target in targets:
            try:
                score = self.score_target(target, context)
                scores.append(score)
            except Exception as e:
                logger.warning(f"Failed to score {target}: {e}")

        scores.sort(key=lambda s: s.total, reverse=True)
        return scores

    def get_queue(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get the current exploration queue from Neo4j."""
        # Find domains/subdomains that haven't been fully explored
        results = cypher_read("""
            MATCH (d:Domain)
            WHERE NOT EXISTS { MATCH (d)-[:HAS_SUBDOMAIN]->() }
            OPTIONAL MATCH (d)-[r:RESOLVES_TO]->(i:IPAddress)
            WITH d, collect(i.ip) AS ips
            WHERE d.hostname IS NOT NULL
            RETURN d.hostname AS target, ips
            LIMIT $limit
        """, {"limit": limit})

        queue = []
        for row in results:
            target = row.get("target", "")
            if target:
                score = self.score_target(target, {"ips": row.get("ips", [])})
                if score.total >= self.threshold:
                    queue.append(score.to_dict())

        queue.sort(key=lambda x: x["total"], reverse=True)
        return queue[:self.max_queue_size]

    def store_score(self, score: CuriosityScore) -> None:
        """Store a curiosity score in Neo4j."""
        import uuid
        cypher_write(
            "MERGE (m:Memory {id: $id}) "
            "SET m.memory_type = 'cartographic', m.content = $content, "
            "m.target = $target, m.severity = $severity, m.timestamp = datetime(), "
            "m.curiosity_score = $score, m.curiosity_priority = $priority",
            {
                "id": str(uuid.uuid4())[:12],
                "content": f"Curiosity: {score.target} scored {score.total} — {score.reason}",
                "target": score.target,
                "severity": "info",
                "score": score.total,
                "priority": score.priority,
            },
        )


# Singleton
curiosity_engine = CuriosityEngine()