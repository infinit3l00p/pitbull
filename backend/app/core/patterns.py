"""PITBULL Pattern Discovery — mines own memory for cross-target patterns.

After exploring enough targets, PITBULL discovers patterns in its own data:
- "Sites using jQuery 1.x have 60% rate of DOM XSS"
- "Subdomains with 'dev' or 'test' are 3x more likely to have exposed configs"
- "Cloudflare-protected sites are harder to explore"

Academic basis:
- Memory Beyond Recall (arXiv:2606.09483): pattern distillation from episodic memory
- Galaxy (arXiv:2508.03991): proactive knowledge gap identification
- WebExplorer (arXiv:2509.06501): exploration-exploitation learning
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter
from datetime import datetime
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)


class PatternDiscovery:
    """Discovers patterns from PITBULL's own exploration history."""

    def discover_patterns(self, min_targets: int = 10) -> dict[str, Any]:
        """Run pattern discovery across all exploration data."""
        results = {
            "patterns_found": 0,
            "patterns": [],
            "insights": [],
            "correlations": [],
        }

        # Check if we have enough data
        target_count = cypher_read("MATCH (d:Domain) RETURN count(d) AS count")
        total_targets = target_count[0]["count"] if target_count else 0

        if total_targets < min_targets:
            results["message"] = f"Not enough targets ({total_targets}/{min_targets}) for pattern discovery"
            return results

        # 1. Technology → Security correlation patterns
        tech_patterns = self._discover_tech_security_patterns()
        results["patterns"].extend(tech_patterns)
        results["patterns_found"] += len(tech_patterns)

        # 2. Subdomain naming patterns
        sub_patterns = self._discover_subdomain_patterns()
        results["patterns"].extend(sub_patterns)
        results["patterns_found"] += len(sub_patterns)

        # 3. Infrastructure correlation patterns
        infra_patterns = self._discover_infrastructure_patterns()
        results["patterns"].extend(infra_patterns)
        results["patterns_found"] += len(infra_patterns)

        # 4. Temporal patterns (when things appear/change)
        temporal_patterns = self._discover_temporal_patterns()
        results["patterns"].extend(temporal_patterns)
        results["patterns_found"] += len(temporal_patterns)

        # 5. Generate insights (higher-level conclusions)
        results["insights"] = self._generate_insights(results["patterns"])

        # 6. Correlation analysis
        results["correlations"] = self._correlation_analysis()

        # Store discovered patterns as semantic memories
        for pattern in results["patterns"]:
            self._store_pattern(pattern)

        logger.info(f"Pattern discovery: {results['patterns_found']} patterns, {len(results['insights'])} insights")
        return results

    def _discover_tech_security_patterns(self) -> list[dict[str, Any]]:
        """Find correlations between technologies and security findings."""
        patterns = []

        # Get all episodic memories that mention tech + security findings
        memories = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.content CONTAINS 'tech=' OR m.content CONTAINS 'interesting_paths=' "
            "RETURN m.content AS content, m.target AS target",
        )

        if not memories:
            return patterns

        # Parse tech and security findings from memory contents
        tech_findings: dict[str, dict[str, int]] = {}  # tech -> {total, with_findings}

        for entry in memories:
            content = entry.get("content", "")
            target = entry.get("target", "")

            # Extract tech hints
            tech_part = ""
            if "tech=" in content:
                tech_part = content.split("tech=")[1].split(",")[0].split(")")[0]

            has_findings = "interesting_paths=" in content and content.split("interesting_paths=")[1].split(")")[0].strip()

            for tech in [t.strip() for t in tech_part.split(",") if t.strip()]:
                if tech not in tech_findings:
                    tech_findings[tech] = {"total": 0, "with_findings": 0}
                tech_findings[tech]["total"] += 1
                if has_findings:
                    tech_findings[tech]["with_findings"] += 1

        # Find patterns where tech has high finding rate
        for tech, counts in tech_findings.items():
            if counts["total"] >= 3:
                rate = counts["with_findings"] / counts["total"]
                if rate > 0.3:
                    patterns.append({
                        "type": "tech_security_correlation",
                        "subject": f"tech:{tech}",
                        "pattern": f"Targets using {tech} have {rate:.0%} rate of interesting findings",
                        "confidence": min(0.95, 0.4 + rate * 0.3),
                        "evidence_count": counts["total"],
                        "finding_rate": rate,
                    })

        return patterns

    def _discover_subdomain_patterns(self) -> list[dict[str, Any]]:
        """Find patterns in subdomain naming and exposure."""
        patterns = []

        # Check for subdomains with dev/test/staging in name
        risky_subs = cypher_read(
            "MATCH (s:Subdomain) "
            "WHERE s.name CONTAINS 'dev' OR s.name CONTAINS 'test' OR s.name CONTAINS 'staging' "
            "OR s.name CONTAINS 'backup' OR s.name CONTAINS 'old' "
            "RETURN count(s) AS risky_count",
        )

        total_subs = cypher_read("MATCH (s:Subdomain) RETURN count(s) AS total")

        risky_count = risky_subs[0]["risky_count"] if risky_subs else 0
        total = total_subs[0]["total"] if total_subs else 0

        if total > 0 and risky_count > 0:
            rate = risky_count / total
            patterns.append({
                "type": "subdomain_naming_pattern",
                "subject": "subdomain:risky_naming",
                "pattern": f"{risky_count} subdomains ({rate:.0%}) have risky names (dev/test/staging/backup/old)",
                "confidence": min(0.9, 0.3 + rate),
                "evidence_count": risky_count,
            })

        return patterns

    def _discover_infrastructure_patterns(self) -> list[dict[str, Any]]:
        """Find patterns in infrastructure (CDNs, hosting, ASNs)."""
        patterns = []

        # CDN usage patterns
        cdn_data = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.content CONTAINS 'Cloudflare' OR m.content CONTAINS 'cloudflare' "
            "RETURN count(m) AS cf_count",
        )

        total_crawls = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "WHERE m.content CONTAINS 'Crawled' "
            "RETURN count(m) AS total",
        )

        cf_count = cdn_data[0]["cf_count"] if cdn_data else 0
        total = total_crawls[0]["total"] if total_crawls else 0

        if total > 0 and cf_count > 0:
            rate = cf_count / total
            patterns.append({
                "type": "infrastructure_pattern",
                "subject": "infra:cdn_usage",
                "pattern": f"{cf_count} of {total} crawled sites ({rate:.0%}) use Cloudflare CDN",
                "confidence": min(0.9, 0.3 + rate * 0.5),
                "evidence_count": cf_count,
            })

        # IP sharing patterns
        shared_ips = cypher_read(
            "MATCH (i:IPAddress)<-[:RESOLVES_TO]-(d1:Domain), (i)<-[:RESOLVES_TO]-(d2:Domain) "
            "WHERE d1.hostname < d2.hostname "
            "RETURN count(DISTINCT i) AS shared_ip_count",
        )

        shared = shared_ips[0]["shared_ip_count"] if shared_ips else 0
        if shared > 0:
            patterns.append({
                "type": "infrastructure_pattern",
                "subject": "infra:ip_sharing",
                "pattern": f"{shared} IP addresses shared between multiple domains — hosting correlation",
                "confidence": 0.6,
                "evidence_count": shared,
            })

        return patterns

    def _discover_temporal_patterns(self) -> list[dict[str, Any]]:
        """Find temporal patterns in exploration data."""
        patterns = []

        # Certificate age patterns
        cert_patterns = cypher_read(
            "MATCH (c:Certificate) "
            "WHERE c.not_before IS NOT NULL "
            "RETURN count(c) AS total, "
            "avg(duration.between(date(substring(c.not_before, 0, 10)), date()).months) AS avg_age_months",
        )

        if cert_patterns and cert_patterns[0].get("total", 0) > 5:
            total = cert_patterns[0]["total"]
            avg_age = cert_patterns[0].get("avg_age_months", 0)
            patterns.append({
                "type": "temporal_pattern",
                "subject": "cert:age_distribution",
                "pattern": f"Average certificate age: {avg_age:.1f} months across {total} certificates",
                "confidence": 0.5,
                "evidence_count": total,
            })

        return patterns

    def _generate_insights(self, patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate higher-level insights from discovered patterns."""
        insights = []

        # Group patterns by type
        by_type: dict[str, list] = {}
        for p in patterns:
            by_type.setdefault(p.get("type", "unknown"), []).append(p)

        # Generate insight: if multiple tech-security correlations exist
        tech_patterns = by_type.get("tech_security_correlation", [])
        if len(tech_patterns) >= 2:
            high_risk_techs = [p["subject"].replace("tech:", "") for p in tech_patterns if p.get("finding_rate", 0) > 0.5]
            if high_risk_techs:
                insights.append({
                    "insight": f"High-risk technology stack detected: {', '.join(high_risk_techs)} — prioritize these in future explorations",
                    "confidence": 0.8,
                    "actionable": True,
                })

        # Generate insight: CDN dominance
        infra_patterns = by_type.get("infrastructure_pattern", [])
        for p in infra_patterns:
            if "Cloudflare" in p.get("pattern", "") and p.get("evidence_count", 0) > 5:
                rate_match = p["pattern"]
                insights.append({
                    "insight": f"CDN dominance detected — {rate_match}. Consider CDN-specific exploration strategies (origin discovery, bypass techniques).",
                    "confidence": 0.7,
                    "actionable": True,
                })

        return insights

    def _correlation_analysis(self) -> list[dict[str, Any]]:
        """Analyze correlations between different data types."""
        correlations = []

        # Domain → IP → Certificate chain analysis
        chains = cypher_read(
            "MATCH (d:Domain)-[:RESOLVES_TO]->(i:IPAddress)<-[:RESOLVES_TO]-(other:Domain)-[:HAS_CERTIFICATE]->(c:Certificate) "
            "WHERE d.hostname <> other.hostname "
            "RETURN count(DISTINCT c) AS shared_certs_via_shared_ips "
            "LIMIT 5",
        )

        if chains and chains[0].get("shared_certs_via_shared_ips", 0) > 0:
            correlations.append({
                "type": "domain_ip_cert_chain",
                "description": f"Found {chains[0]['shared_certs_via_shared_ips']} certificates reachable through shared IP infrastructure",
                "significance": "Infrastructure overlap — targets may be related",
            })

        return correlations

    def _store_pattern(self, pattern: dict[str, Any]) -> None:
        """Store a discovered pattern in Neo4j as semantic memory."""
        existing = cypher_read(
            "MATCH (m:Memory {memory_type: 'semantic', subject: $subject}) RETURN m",
            {"subject": pattern["subject"]},
        )

        if existing:
            cypher_write(
                "MATCH (m:Memory {memory_type: 'semantic', subject: $subject}) "
                "SET m.content = $content, m.confidence = $conf, "
                "m.last_updated = datetime(), m.evidence_count = $count, "
                "m.rule_type = 'discovered_pattern'",
                {
                    "subject": pattern["subject"],
                    "content": pattern["pattern"],
                    "conf": pattern.get("confidence", 0.5),
                    "count": pattern.get("evidence_count", 1),
                },
            )
        else:
            cypher_write(
                "CREATE (m:Memory {id: $id}) "
                "SET m.memory_type = 'semantic', m.subject = $subject, "
                "m.content = $content, m.confidence = $conf, "
                "m.evidence_count = $count, m.rule_type = 'discovered_pattern', "
                "m.first_formed = datetime(), m.last_updated = datetime()",
                {
                    "id": str(uuid.uuid4())[:12],
                    "subject": pattern["subject"],
                    "content": pattern["pattern"],
                    "conf": pattern.get("confidence", 0.5),
                    "count": pattern.get("evidence_count", 1),
                },
            )

    def identify_knowledge_gaps(self) -> list[dict[str, Any]]:
        """Identify what PITBULL hasn't explored yet — knowledge gaps."""
        gaps = []

        # Check what technologies we haven't seen
        known_techs = cypher_read(
            "MATCH (m:Memory {memory_type: 'semantic'}) "
            "WHERE m.subject STARTS WITH 'tech:' "
            "RETURN m.subject AS tech",
        )
        seen_techs = {r["tech"].replace("tech:", "") for r in known_techs}

        important_techs = [
            "GraphQL", "Kubernetes", "Docker", "Jenkins", "Grafana",
            "Kibana", "Elasticsearch", "Redis", "RabbitMQ", "Kafka",
            "Nginx", "Apache", "WordPress", "Drupal", "Joomla",
            "React", "Vue", "Angular", "Next.js", "Django", "Flask",
            "Spring", "Tomcat", "IIS", "Caddy",
        ]

        unseen = [t for t in important_techs if t.lower() not in seen_techs]
        if unseen:
            gaps.append({
                "gap_type": "unseen_technologies",
                "description": f"Haven't encountered {len(unseen)} important technologies yet",
                "items": unseen[:15],
                "suggestion": "Explore targets likely to use these technologies",
            })

        # Check what exploration scopes we haven't used
        scopes = cypher_read(
            "MATCH (m:Memory) WHERE m.content CONTAINS 'scope=' "
            "RETURN DISTINCT split(split(m.content, 'scope=')[1], ')')[0] AS scope LIMIT 10",
        )
        used_scopes = {r.get("scope", "").strip() for r in scopes if r.get("scope")}
        unused_scopes = {"surface", "deep", "darknet", "full"} - used_scopes
        if unused_scopes:
            gaps.append({
                "gap_type": "unexplored_scopes",
                "description": f"Haven't used these exploration scopes: {', '.join(unused_scopes)}",
                "items": list(unused_scopes),
                "suggestion": "Try these scopes on known targets",
            })

        return gaps


pattern_discovery = PatternDiscovery()