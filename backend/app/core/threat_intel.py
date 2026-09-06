"""PITBULL Threat Intelligence — CVE, OWASP, and ATT&CK knowledge with periodic updates.

Automatically fetches and updates:
- Recent CVEs from NVD (daily)
- Technology-specific CVEs (on demand)
- OWASP Top 10:2025 knowledge
- Maps CVEs to ATT&CK techniques
- Stores everything in Neo4j

Runs as a background task via cron/heartbeat.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

import httpx

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)

# OWASP Top 10:2025 — full knowledge base
OWASP_TOP_10_2025 = [
    {
        "id": "A01",
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are not properly enforced.",
        "common_issues": ["missing function-level access control", "insecure direct object references (IDOR)", "path traversal", "CORS misconfiguration", "force browsing to authenticated pages"],
        "pitbull_detection": ["admin panels found via deep probe", "API endpoints without auth", "IDOR in URL parameters", "path traversal in interesting_paths"],
        "attack_techniques": ["T1190", "T1078", "T1068"],
    },
    {
        "id": "A02",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography that lead to sensitive data exposure or system compromise.",
        "common_issues": ["weak ciphers (DES, 3DES, MD5, SHA1)", "hardcoded credentials", "lack of TLS enforcement", "weak random number generation", "sensitive data in plaintext"],
        "pitbull_detection": ["expired certificates", "self-signed certificates", "HTTP without HTTPS redirect", "weak TLS in headers"],
        "attack_techniques": ["T1552", "T1040"],
    },
    {
        "id": "A03",
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized, leading to SQL, NoSQL, OS, or LDAP injection.",
        "common_issues": ["SQL injection", "NoSQL injection", "OS command injection", "LDAP injection", "template injection", "expression language injection"],
        "pitbull_detection": ["form fields found during crawl", "API endpoints with query parameters", "login forms", "search functionality"],
        "attack_techniques": ["T1190", "T1059"],
    },
    {
        "id": "A04",
        "name": "Insecure Design",
        "description": "Flaws in architecture or design that cannot be fixed by implementation alone.",
        "common_issues": ["missing rate limiting", "lack of defense in depth", "trust boundary violations", "insecure business logic"],
        "pitbull_detection": ["no rate limiting detected", "API endpoints without throttling", "business logic endpoints"],
        "attack_techniques": ["T1110", "T1190"],
    },
    {
        "id": "A05",
        "name": "Security Misconfiguration",
        "description": "Improperly configured security settings or unnecessary features enabled.",
        "common_issues": ["default credentials", "unnecessary features enabled", "error messages with stack traces", "unpatched flaws", "directory listing enabled", ".git/.env exposed"],
        "pitbull_detection": ["exposed .git directories", "exposed .env files", "debug endpoints", "actuator endpoints", "server-status", "directory listing", "default pages"],
        "attack_techniques": ["T1552", "T1213"],
    },
    {
        "id": "A06",
        "name": "Vulnerable and Outdated Components",
        "description": "Using libraries, frameworks, or components with known vulnerabilities.",
        "common_issues": ["outdated jQuery", "old WordPress plugins", "deprecated server software", "unpatched CVEs in tech stack"],
        "pitbull_detection": ["tech_hints from crawler", "version detection in headers", "jQuery version in page source", "WordPress version in meta generator"],
        "attack_techniques": ["T1190", "T1210"],
    },
    {
        "id": "A07",
        "name": "Identification and Authentication Failures",
        "description": "Weaknesses in authentication and session management.",
        "common_issues": ["weak password policies", "no MFA", "session fixation", "credential stuffing", "broken session management"],
        "pitbull_detection": ["login forms without CSRF tokens", "auth forms detected", "JWT in URLs", "session cookies without Secure/HttpOnly flags"],
        "attack_techniques": ["T1110", "T1078"],
    },
    {
        "id": "A08",
        "name": "Integrity Failures",
        "description": "Code and data integrity are not verified — untrusted sources, untrusted CDNs, unsigned updates.",
        "common_issues": ["unsigned software updates", "untrusted CDN for scripts", "no SRI on script tags", "deserialization of untrusted data"],
        "pitbull_detection": ["scripts loaded from external CDNs without SRI", "untrusted script sources", "software update mechanisms"],
        "attack_techniques": ["T1195", "T1078"],
    },
    {
        "id": "A09",
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, monitoring, and alerting to detect active attacks.",
        "common_issues": ["no logging of security events", "no monitoring of suspicious activity", "no alerting on attacks", "logs not secured"],
        "pitbull_detection": ["no security.txt", "no logging API endpoints", "error responses with detailed stack traces"],
        "attack_techniques": ["T1562", "T1070"],
    },
    {
        "id": "A10",
        "name": "Mishandling Exceptional Conditions",
        "description": "Applications fail to handle edge cases and exceptional conditions safely.",
        "common_issues": ["unhandled exceptions revealing sensitive info", "race conditions", "denial of service from uncontrolled resource allocation", "error messages with system paths"],
        "pitbull_detection": ["stack traces in responses", "debug mode enabled", "actuator/env endpoints", "verbose error messages"],
        "attack_techniques": ["T1499", "T1190"],
    },
]


class ThreatIntelligence:
    """Manages CVE, OWASP, and threat knowledge with periodic updates."""

    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.client = httpx.AsyncClient(timeout=45.0, verify=False, follow_redirects=True)
        self.last_cve_update: datetime | None = None
        self.last_owasp_update: datetime | None = None

    async def _nvd_get(self, params: dict[str, str]) -> dict[str, Any] | None:
        """Fetch from NVD using curl (httpx is unreliable behind some local egress proxies)."""
        import subprocess
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{self.nvd_url}?{query}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "env", "-u", "http_proxy", "-u", "https_proxy",
                "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY",
                "-u", "ALL_PROXY", "-u", "all_proxy",
                "curl", "-sk", "--connect-timeout", "30", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error(f"NVD curl failed: {stderr.decode()[:200]}")
                return None
            return json.loads(stdout.decode())
        except Exception as e:
            logger.error(f"NVD fetch error: {e}")
            return None
        self.last_cve_update: datetime | None = None
        self.last_owasp_update: datetime | None = None

    # ── CVE Updates ──────────────────────────────────────────────────

    async def update_cves(self, days: int = 7, max_results: int = 50) -> dict[str, Any]:
        """Fetch recent CVEs from NVD and store in Neo4j."""
        pub_start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end = datetime.now().strftime("%Y-%m-%dT23:59:59.999")
        
        try:
            data = await self._nvd_get({
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": str(max_results),
            })
            if data is None:
                return {"error": "NVD fetch failed", "cves": [], "count": 0}
            cves_stored = 0

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0) if cvss_data else 0
                severity = cvss_data[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN") if cvss_data else "UNKNOWN"

                weaknesses = []
                for w in cve.get("weaknesses", []):
                    for wd in w.get("description", []):
                        if wd.get("lang") == "en":
                            weaknesses.append(wd.get("value", ""))

                # Extract affected products
                configs = cve.get("configurations", [])
                affected_products = []
                for config in configs:
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            cpe = cpe_match.get("criteria", "")
                            if cpe:
                                # Extract product from CPE URI
                                parts = cpe.split(":")
                                if len(parts) >= 5:
                                    affected_products.append(f"{parts[3]} {parts[4]}")

                # Map to ATT&CK techniques based on weakness
                attack_mapping = self._map_cve_to_attack(weaknesses, desc, affected_products)

                cypher_write(
                    "MERGE (c:CVE {cve_id: $id}) "
                    "SET c.description = $desc, c.cvss_v3_score = $score, "
                    "c.severity = $sev, c.published_date = $pub, "
                    "c.modified_date = $mod, c.weaknesses = $weak, "
                    "c.affected_products = $products, "
                    "c.attack_techniques = $attack, c.last_updated = datetime()",
                    {
                        "id": cve_id,
                        "desc": desc[:1000],
                        "score": cvss_score,
                        "sev": severity,
                        "pub": cve.get("published", ""),
                        "mod": cve.get("lastModified", ""),
                        "weak": weaknesses[:5],
                        "products": list(set(affected_products))[:10],
                        "attack": attack_mapping,
                    },
                )

                # Link CVE to ATT&CK techniques in graph
                for tech_id in attack_mapping:
                    cypher_write(
                        "MERGE (t:ATTACKTechnique {id: $tech_id}) "
                        "MERGE (c:CVE {cve_id: $cve_id}) "
                        "MERGE (c)-[:RELATES_TO_TECHNIQUE]->(t)",
                        {"tech_id": tech_id, "cve_id": cve_id},
                    )

                cves_stored += 1

            self.last_cve_update = datetime.now()
            logger.info(f"Updated {cves_stored} CVEs from NVD (last {days} days)")
            return {"cves_updated": cves_stored, "days_range": days, "updated_at": self.last_cve_update.isoformat()}

        except Exception as e:
            logger.error(f"CVE update failed: {e}")
            return {"error": str(e), "cves_updated": 0}

    async def update_tech_cves(self, technologies: list[str], max_per_tech: int = 10) -> dict[str, Any]:
        """Fetch CVEs for specific technologies."""
        total = 0
        results = {}
        for tech in technologies:
            try:
                data = await self._nvd_get({
                    "keywordSearch": tech,
                    "resultsPerPage": str(max_per_tech),
                })
                if data is None:
                    results[tech] = "fetch failed"
                    continue
                count = 0
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue

                    descriptions = cve.get("descriptions", [])
                    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                    cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0) if cvss_data else 0
                    severity = cvss_data[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN") if cvss_data else "UNKNOWN"

                    cypher_write(
                        "MERGE (c:CVE {cve_id: $id}) "
                        "SET c.description = $desc, c.cvss_v3_score = $score, "
                        "c.severity = $sev, c.technology = $tech, "
                        "c.published_date = $pub, c.last_updated = datetime()",
                        {
                            "id": cve_id,
                            "desc": desc[:1000],
                            "score": cvss_score,
                            "sev": severity,
                            "tech": tech,
                            "pub": cve.get("published", ""),
                        },
                    )
                    count += 1

                results[tech] = count
                total += count
                await asyncio.sleep(0.6)  # NVD rate limit: 5 req/30s without API key

            except Exception as e:
                results[tech] = f"error: {e}"

        logger.info(f"Updated {total} technology-specific CVEs for {len(technologies)} technologies")
        return {"technologies": results, "total_cves": total}

    def _map_cve_to_attack(self, weaknesses: list[str], description: str, products: list[str]) -> list[str]:
        """Map a CVE to ATT&CK techniques based on weakness types and description."""
        mappings = []
        desc_lower = description.lower()
        weakness_str = " ".join(weaknesses).lower()

        # CWE-based mapping
        if "sql injection" in desc_lower or "sqli" in desc_lower or "cwe-89" in weakness_str:
            mappings.append("T1190")
        if "xss" in desc_lower or "cross-site scripting" in desc_lower or "cwe-79" in weakness_str:
            mappings.append("T1059")
        if "rce" in desc_lower or "remote code execution" in desc_lower or "cwe-94" in weakness_str:
            mappings.append("T1190")
            mappings.append("T1059")
        if "path traversal" in desc_lower or "directory traversal" in desc_lower or "cwe-22" in weakness_str:
            mappings.append("T1190")
            mappings.append("T1083")
        if "ssrf" in desc_lower or "server-side request forgery" in desc_lower or "cwe-918" in weakness_str:
            mappings.append("T1190")
        if "deserialization" in desc_lower or "cwe-502" in weakness_str:
            mappings.append("T1059")
            mappings.append("T1190")
        if "auth" in desc_lower and ("bypass" in desc_lower or "weakness" in desc_lower):
            mappings.append("T1078")
        if "privilege escalation" in desc_lower or "cwe-269" in weakness_str:
            mappings.append("T1068")
        if "information disclosure" in desc_lower or "cwe-200" in weakness_str:
            mappings.append("T1552")
        if "dos" in desc_lower or "denial of service" in desc_lower or "cwe-400" in weakness_str:
            mappings.append("T1499")
        if "xxe" in desc_lower or "xml external entity" in desc_lower or "cwe-611" in weakness_str:
            mappings.append("T1059")

        # Default: if it's a web vulnerability, map to T1190
        if not mappings and any(kw in desc_lower for kw in ["web", "http", "api", "endpoint", "application"]):
            mappings.append("T1190")

        return list(set(mappings))

    # ── OWASP Knowledge ─────────────────────────────────────────────

    def load_owasp_knowledge(self) -> dict[str, Any]:
        """Load OWASP Top 10:2025 knowledge into Neo4j."""
        loaded = 0
        for item in OWASP_TOP_10_2025:
            cypher_write(
                "MERGE (o:OWASPCategory {id: $id}) "
                "SET o.name = $name, o.description = $desc, "
                "o.common_issues = $issues, o.pitbull_detection = $detection, "
                "o.attack_techniques = $techniques, o.version = '2025', "
                "o.last_updated = datetime()",
                {
                    "id": item["id"],
                    "name": item["name"],
                    "desc": item["description"],
                    "issues": item["common_issues"],
                    "detection": item["pitbull_detection"],
                    "techniques": item["attack_techniques"],
                },
            )

            # Link OWASP categories to ATT&CK techniques
            for tech_id in item["attack_techniques"]:
                cypher_write(
                    "MERGE (o:OWASPCategory {id: $owasp_id}) "
                    "MERGE (t:ATTACKTechnique {id: $tech_id}) "
                    "MERGE (o)-[:MAPS_TO_TECHNIQUE]->(t)",
                    {"owasp_id": item["id"], "tech_id": tech_id},
                )

            loaded += 1

        self.last_owasp_update = datetime.now()
        logger.info(f"Loaded {loaded} OWASP Top 10:2025 categories into Neo4j")
        return {"owasp_loaded": loaded, "version": "2025", "updated_at": self.last_owasp_update.isoformat()}

    def get_owasp_categories(self) -> list[dict[str, Any]]:
        """Get all OWASP categories from Neo4j."""
        results = cypher_read("MATCH (o:OWASPCategory) RETURN o ORDER BY o.id")
        categories = []
        for row in results:
            o = row.get("o", {})
            categories.append({
                "id": o.get("id", ""),
                "name": o.get("name", ""),
                "description": o.get("description", ""),
                "common_issues": o.get("common_issues", []),
                "pitbull_detection": o.get("pitbull_detection", []),
                "attack_techniques": o.get("attack_techniques", []),
                "version": o.get("version", ""),
            })
        return categories

    # ── Combined Stats ──────────────────────────────────────────────

    def get_threat_stats(self) -> dict[str, Any]:
        """Get threat intelligence statistics."""
        cve_count = cypher_read("MATCH (c:CVE) RETURN count(c) AS count")
        cve_critical = cypher_read("MATCH (c:CVE) WHERE c.severity = 'CRITICAL' RETURN count(c) AS count")
        cve_high = cypher_read("MATCH (c:CVE) WHERE c.severity = 'HIGH' RETURN count(c) AS count")
        owasp_count = cypher_read("MATCH (o:OWASPCategory) RETURN count(o) AS count")
        attack_count = cypher_read("MATCH (t:ATTACKTechnique) RETURN count(t) AS count")
        cve_attack_links = cypher_read("MATCH (c:CVE)-[:RELATES_TO_TECHNIQUE]->(t:ATTACKTechnique) RETURN count(DISTINCT c) AS count")

        # CVEs by severity
        by_severity = cypher_read(
            "MATCH (c:CVE) RETURN c.severity AS severity, count(c) AS count ORDER BY count DESC"
        )
        # CVEs by technology
        by_tech = cypher_read(
            "MATCH (c:CVE) WHERE c.technology IS NOT NULL "
            "RETURN c.technology AS tech, count(c) AS count ORDER BY count DESC LIMIT 10"
        )

        return {
            "cves_total": cve_count[0]["count"] if cve_count else 0,
            "cves_critical": cve_critical[0]["count"] if cve_critical else 0,
            "cves_high": cve_high[0]["count"] if cve_high else 0,
            "owasp_categories": owasp_count[0]["count"] if owasp_count else 0,
            "attack_techniques": attack_count[0]["count"] if attack_count else 0,
            "cve_attack_mappings": cve_attack_links[0]["count"] if cve_attack_links else 0,
            "cves_by_severity": {r.get("severity", "?"): r.get("count", 0) for r in by_severity},
            "cves_by_technology": {r.get("tech", "?"): r.get("count", 0) for r in by_tech},
            "last_cve_update": self.last_cve_update.isoformat() if self.last_cve_update else None,
            "last_owasp_update": self.last_owasp_update.isoformat() if self.last_owasp_update else None,
        }

    # ── Full Update ─────────────────────────────────────────────────

    async def full_update(self) -> dict[str, Any]:
        """Run a full threat intelligence update — CVEs + OWASP."""
        results = {}
        
        # Load OWASP
        results["owasp"] = self.load_owasp_knowledge()
        
        # Update recent CVEs
        results["cves"] = await self.update_cves(days=30, max_results=50)
        
        # Update technology-specific CVEs for common tech
        techs = ["nginx", "apache", "wordpress", "php", "docker", "kubernetes", "jenkins", "grafana"]
        results["tech_cves"] = await self.update_tech_cves(techs, max_per_tech=5)
        
        stats = self.get_threat_stats()
        results["stats"] = stats
        
        logger.info(f"Threat intelligence full update complete: {stats['cves_total']} CVEs, {stats['owasp_categories']} OWASP categories, {stats['attack_techniques']} ATT&CK techniques")
        return results

    # ── Findings → OWASP Mapping ────────────────────────────────────

    def map_finding_to_owasp(self, finding_type: str, finding_content: str) -> list[dict[str, Any]]:
        """Map an PITBULL finding to OWASP Top 10 categories."""
        content_lower = finding_content.lower()
        mappings = []

        # A01: Broken Access Control
        if any(kw in content_lower for kw in ["admin", "panel", "unauthorized", "idor", "path traversal", "bypass"]):
            mappings.append({"owasp": "A01", "name": "Broken Access Control", "confidence": 0.8})

        # A02: Cryptographic Failures
        if any(kw in content_lower for kw in ["expired cert", "self-signed", "weak cipher", "no https", "tls", "ssl"]):
            mappings.append({"owasp": "A02", "name": "Cryptographic Failures", "confidence": 0.75})

        # A03: Injection
        if any(kw in content_lower for kw in ["sqli", "sql injection", "xss", "command injection", "graphql"]):
            mappings.append({"owasp": "A03", "name": "Injection", "confidence": 0.85})

        # A05: Security Misconfiguration
        if any(kw in content_lower for kw in [".git", ".env", "debug", "actuator", "server-status", "directory listing", "default page", "backup", "config exposed"]):
            mappings.append({"owasp": "A05", "name": "Security Misconfiguration", "confidence": 0.9})

        # A06: Vulnerable Components
        if any(kw in content_lower for kw in ["outdated", "old version", "jquery 1", "wordpress", "php 5", "deprecated"]):
            mappings.append({"owasp": "A06", "name": "Vulnerable and Outdated Components", "confidence": 0.75})

        # A07: Auth Failures
        if any(kw in content_lower for kw in ["login form", "auth", "password", "session", "jwt", "credential"]):
            mappings.append({"owasp": "A07", "name": "Identification and Authentication Failures", "confidence": 0.7})

        # A08: Integrity Failures
        if any(kw in content_lower for kw in ["cdn", "unsigned", "sri", "integrity", "untrusted"]):
            mappings.append({"owasp": "A08", "name": "Integrity Failures", "confidence": 0.6})

        # A09: Logging Failures
        if any(kw in content_lower for kw in ["no logging", "stack trace", "verbose error", "debug mode"]):
            mappings.append({"owasp": "A09", "name": "Security Logging and Monitoring Failures", "confidence": 0.65})

        # A10: Mishandling Exceptional Conditions
        if any(kw in content_lower for kw in ["stack trace", "error handling", "race condition", "dos", "denial of service"]):
            mappings.append({"owasp": "A10", "name": "Mishandling Exceptional Conditions", "confidence": 0.6})

        return mappings

    def map_mission_to_owasp(self, target: str) -> dict[str, Any]:
        """Map all findings from a mission to OWASP categories."""
        memories = cypher_read(
            "MATCH (m:Memory) WHERE m.target CONTAINS $target AND m.content IS NOT NULL "
            "RETURN m.content AS content, m.memory_type AS type, m.severity AS severity "
            "ORDER BY m.timestamp DESC LIMIT 200",
            {"target": target},
        )

        owasp_mappings: dict[str, dict] = {}
        for entry in memories:
            content = entry.get("content", "")
            mtype = entry.get("type", "")
            mappings = self.map_finding_to_owasp(mtype, content)

            for mapping in mappings:
                owasp_id = mapping["owasp"]
                if owasp_id not in owasp_mappings:
                    owasp_mappings[owasp_id] = {
                        "owasp_id": owasp_id,
                        "name": mapping["name"],
                        "confidence": mapping["confidence"],
                        "finding_count": 0,
                        "findings": [],
                    }
                owasp_mappings[owasp_id]["finding_count"] += 1
                owasp_mappings[owasp_id]["findings"].append(content[:100])

        # Store OWASP mappings in Neo4j
        for owasp_id, data in owasp_mappings.items():
            cypher_write(
                "MERGE (o:OWASPCategory {id: $owasp_id}) "
                "MERGE (d:Domain {hostname: $target}) "
                "MERGE (d)-[:HAS_VULNERABILITY]->(o) "
                "SET o.last_mapped = datetime(), o.finding_count = $count",
                {
                    "owasp_id": owasp_id,
                    "target": target,
                    "count": data["finding_count"],
                },
            )

        sorted_mappings = sorted(owasp_mappings.values(), key=lambda x: x["finding_count"], reverse=True)

        return {
            "target": target,
            "owasp_categories_mapped": len(sorted_mappings),
            "mappings": sorted_mappings,
        }


threat_intelligence = ThreatIntelligence()