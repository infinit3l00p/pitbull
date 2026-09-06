"""PITBULL Knowledge Expansion — studies CVEs, ATT&CK, and security research.

Between missions, PITBULL proactively studies to fill knowledge gaps.
It identifies what it doesn't know and learns about it.

Academic basis:
- Galaxy (arXiv:2508.03991): proactive knowledge expansion
- PTFusion (Information Fusion 2026): multi-source knowledge fusion
- CurriculumPT (MDPI 2025): graduated learning curriculum
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

import httpx

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)


class KnowledgeExpander:
    """Expands PITBULL's knowledge between missions."""

    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.client = httpx.AsyncClient(timeout=30.0, trust_env=False)

    async def study_recent_cves(self, days: int = 30, max_results: int = 20) -> dict[str, Any]:
        """Study recent CVEs from NVD."""
        pub_start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
        try:
            resp = await self.client.get(
                self.nvd_url,
                params={
                    "pubStartDate": pub_start,
                    "resultsPerPage": str(max_results),
                },
            )
            if resp.status_code != 200:
                return {"error": f"NVD returned {resp.status_code}", "cves": []}

            data = resp.json()
            cves = []

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                # Get CVSS score
                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0) if cvss_data else 0
                severity = cvss_data[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN") if cvss_data else "UNKNOWN"

                # Get weaknesses
                weaknesses = [w.get("description", [{}])[0].get("value", "") for w in cve.get("weaknesses", [])]

                cve_entry = {
                    "id": cve_id,
                    "description": desc[:300],
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "weaknesses": weaknesses,
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                }
                cves.append(cve_entry)

                # Store in Neo4j
                cypher_write(
                    "MERGE (c:CVE {cve_id: $id}) "
                    "SET c.description = $desc, c.cvss_v3_score = $score, "
                    "c.severity = $sev, c.published_date = $pub, "
                    "c.modified_date = $mod, c.first_seen = datetime()",
                    {
                        "id": cve_id,
                        "desc": desc[:500],
                        "score": cvss_score,
                        "sev": severity,
                        "pub": cve.get("published", ""),
                        "mod": cve.get("lastModified", ""),
                    },
                )

            logger.info(f"Studied {len(cves)} recent CVEs")
            return {"cves": cves, "count": len(cves), "days_range": days}

        except Exception as e:
            logger.error(f"CVE study failed: {e}")
            return {"error": str(e), "cves": [], "count": 0}

    async def study_cve_for_tech(self, technology: str, max_results: int = 10) -> dict[str, Any]:
        """Study CVEs related to a specific technology."""
        try:
            resp = await self.client.get(
                self.nvd_url,
                params={
                    "keywordSearch": technology,
                    "resultsPerPage": str(max_results),
                },
            )
            if resp.status_code != 200:
                return {"error": f"NVD returned {resp.status_code}"}

            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0) if cvss_data else 0

                cves.append({
                    "id": cve_id,
                    "description": desc[:200],
                    "cvss_score": cvss_score,
                    "published": cve.get("published", ""),
                })

            # Store as semantic memory
            if cves:
                cypher_write(
                    "CREATE (m:Memory {id: $id}) "
                    "SET m.memory_type = 'semantic', m.subject = $subject, "
                    "m.content = $content, m.rule_type = 'cve_knowledge', "
                    "m.confidence = 0.9, m.evidence_count = $count, "
                    "m.first_formed = datetime(), m.last_updated = datetime()",
                    {
                        "id": str(uuid.uuid4())[:12],
                        "subject": f"cve:{technology.lower()}",
                        "content": f"Studied {len(cves)} CVEs for {technology}: {', '.join(c['id'] for c in cves[:5])}",
                        "count": len(cves),
                    },
                )

            return {"technology": technology, "cves": cves, "count": len(cves)}

        except Exception as e:
            return {"error": str(e)}

    def get_study_plan(self) -> list[dict[str, Any]]:
        """Generate a study plan based on knowledge gaps."""
        # What technologies have we encountered?
        known = cypher_read(
            "MATCH (m:Memory {memory_type: 'semantic'}) "
            "WHERE m.subject STARTS WITH 'tech:' OR m.subject STARTS WITH 'cve:' "
            "RETURN m.subject AS subject, m.evidence_count AS count",
        )

        studied_cves = {r["subject"] for r in known if r.get("subject", "").startswith("cve:")}
        known_techs = {r["subject"].replace("tech:", "") for r in known if r.get("subject", "").startswith("tech:")}

        # Priority study topics
        study_plan = []

        # High-priority technologies to study CVEs for
        priority_techs = ["WordPress", "Nginx", "Apache", "PHP", "Cloudflare"]
        for tech in priority_techs:
            if f"cve:{tech.lower()}" not in studied_cves:
                study_plan.append({
                    "topic": tech,
                    "type": "cve_study",
                    "priority": "high" if tech in known_techs else "medium",
                    "reason": f"{'Encountered' if tech in known_techs else 'Important'} but no CVE knowledge",
                })

        # Add general study topics
        study_plan.append({
            "topic": "OWASP Top 10:2025",
            "type": "framework_study",
            "priority": "high",
            "reason": "Core web security knowledge",
        })
        study_plan.append({
            "topic": "MITRE ATT&CK v19",
            "type": "framework_study",
            "priority": "high",
            "reason": "Attack technique knowledge",
        })

        return study_plan

    def get_knowledge_stats(self) -> dict[str, Any]:
        """Get statistics about PITBULL's knowledge base."""
        cve_count = cypher_read("MATCH (c:CVE) RETURN count(c) AS count")
        semantic_count = cypher_read("MATCH (m:Memory {memory_type: 'semantic'}) RETURN count(m) AS count")
        procedural_count = cypher_read("MATCH (m:Memory {memory_type: 'procedural'}) RETURN count(m) AS count")
        episodic_count = cypher_read("MATCH (m:Memory {memory_type: 'episodic'}) RETURN count(m) AS count")

        # Knowledge domains
        domains = cypher_read(
            "MATCH (m:Memory {memory_type: 'semantic'}) "
            "RETURN m.rule_type AS type, count(m) AS count "
            "ORDER BY count DESC",
        )

        return {
            "cves_known": cve_count[0]["count"] if cve_count else 0,
            "semantic_rules": semantic_count[0]["count"] if semantic_count else 0,
            "procedural_memories": procedural_count[0]["count"] if procedural_count else 0,
            "episodic_memories": episodic_count[0]["count"] if episodic_count else 0,
            "knowledge_domains": {r.get("type", "unknown"): r.get("count", 0) for r in domains},
        }


knowledge_expander = KnowledgeExpander()