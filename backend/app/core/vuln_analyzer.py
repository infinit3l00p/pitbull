"""PITBULL Vulnerability Analyzer — post-recon vuln classification.

Takes raw findings from deep web probes, web crawls, and other collectors
and classifies them into actual vulnerability classes that the exploit
engine can target.

This bridges the gap between "found an admin panel at /admin (403)" and
"this is an admin_panel finding with auth_bypass potential".
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from typing import Any

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)


# ── Vulnerability classification rules ──────────────────────────────

# Map deep web probe finding types → vulnerability classes
PROBE_TYPE_TO_VULN: dict[str, dict[str, Any]] = {
    "exposed_config": {
        "vuln_class": "path_traversal",
        "severity": "critical",
        "description": "Exposed configuration file — may contain credentials",
        "exploit_hints": {"paths": ["/.env", "/config.php", "/config.json", "/docker-compose.yml"]},
    },
    "exposed_git": {
        "vuln_class": "path_traversal",
        "severity": "critical",
        "description": "Exposed .git directory — source code and history leaked",
        "exploit_hints": {"paths": ["/.git/HEAD", "/.git/config", "/.git/index"]},
    },
    "backup_file": {
        "vuln_class": "path_traversal",
        "severity": "critical",
        "description": "Backup file accessible — may contain sensitive data",
        "exploit_hints": {"paths": ["/backup.sql", "/dump.sql", "/db.bak"]},
    },
    "debug_endpoint": {
        "vuln_class": "auth_bypass",
        "severity": "high",
        "description": "Debug/actuator endpoint exposed — info disclosure + potential RCE",
        "exploit_hints": {"paths": ["/actuator/env", "/actuator/heapdump", "/debug", "/phpinfo"]},
    },
    "admin_panel": {
        "vuln_class": "auth_bypass",
        "severity": "high",
        "description": "Admin panel discovered — potential auth bypass via default creds or JWT manipulation",
        "exploit_hints": {"paths": ["/admin", "/wp-admin", "/dashboard", "/console"]},
    },
    "api_documentation": {
        "vuln_class": "ssti",
        "severity": "medium",
        "description": "API documentation exposed — reveals endpoints for targeted attacks",
        "exploit_hints": {"paths": ["/swagger", "/openapi", "/api-docs"]},
    },
    "graphql_endpoint": {
        "vuln_class": "sqli",
        "severity": "high",
        "description": "GraphQL endpoint discovered — potential injection via queries",
        "exploit_hints": {"paths": ["/graphql", "/api/graphql"]},
    },
    "api_endpoint": {
        "vuln_class": "sqli",
        "severity": "medium",
        "description": "API endpoint discovered — test for injection and auth bypass",
        "exploit_hints": {"paths": ["/api", "/api/v1", "/api/v2"]},
    },
    "auth_form": {
        "vuln_class": "auth_bypass",
        "severity": "medium",
        "description": "Authentication form found — test for SQLi login bypass and JWT issues",
        "exploit_hints": {"paths": ["/login", "/signin"]},
    },
    "protected_resource": {
        "vuln_class": "auth_bypass",
        "severity": "medium",
        "description": "Protected resource (401/403) — test auth bypass methods",
        "exploit_hints": {"paths": []},
    },
}

# Content-based detection patterns for crawl results
CONTENT_VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": re.compile(r"(?: UNION SELECT | OR 1=1|';.*--|information_schema)", re.I),
        "vuln_class": "sqli",
        "severity": "high",
        "description": "SQL-related content detected in response — potential SQLi",
    },
    {
        "pattern": re.compile(r"(?:<script|onerror=|onload=|javascript:|alert\()", re.I),
        "vuln_class": "xss",
        "severity": "high",
        "description": "Script tags or event handlers in response — potential XSS reflection",
    },
    {
        "pattern": re.compile(r"(?:169\.254\.169\.254|metadata|cloud-init|iam-role)", re.I),
        "vuln_class": "ssrf",
        "severity": "critical",
        "description": "Cloud metadata references found — SSRF could expose credentials",
    },
    {
        "pattern": re.compile(r"(?:eyJ[a-zA-Z0-9_-]+\.eyJ|jwt|bearer\s+[a-zA-Z0-9])", re.I),
        "vuln_class": "auth_bypass",
        "severity": "high",
        "description": "JWT token detected — test for alg=none and weak secret",
    },
    {
        "pattern": re.compile(r"(?:\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\})", re.I),
        "vuln_class": "ssti",
        "severity": "high",
        "description": "Template expressions detected — potential SSTI",
    },
    {
        "pattern": re.compile(r"(?:cmd|exec|system|shell|bash|powershell|wget|curl)\s*[=(]", re.I),
        "vuln_class": "command_injection",
        "severity": "high",
        "description": "Command execution patterns in response — potential RCE",
    },
    {
        "pattern": re.compile(r"(?:O:\d+:|unserialize|deserialize|__wakeup|__destruct)", re.I),
        "vuln_class": "deserialization",
        "severity": "critical",
        "description": "Serialization patterns detected — potential deserialization RCE",
    },
    {
        "pattern": re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)", re.I),
        "vuln_class": "path_traversal",
        "severity": "high",
        "description": "Path traversal patterns detected — LFI/RFI potential",
    },
]

# Tech stack → likely vulnerability classes
TECH_TO_VULN: dict[str, list[str]] = {
    "php": ["sqli", "xss", "path_traversal", "ssti", "deserialization", "command_injection"],
    "wordpress": ["sqli", "xss", "auth_bypass", "path_traversal"],
    "drupal": ["sqli", "xss", "auth_bypass", "deserialization"],
    "jenkins": ["auth_bypass", "command_injection", "deserialization", "ssti"],
    "gitlab": ["sqli", "ssti", "command_injection", "auth_bypass"],
    "node": ["sqli", "ssrf", "auth_bypass", "command_injection"],
    "express": ["sqli", "ssrf", "auth_bypass"],
    "django": ["sqli", "ssti", "xss"],
    "flask": ["ssti", "ssrf", "auth_bypass"],
    "rails": ["sqli", "ssti", "deserialization"],
    "tomcat": ["deserialization", "auth_bypass", "path_traversal"],
    "nginx": ["path_traversal"],
    "apache": ["path_traversal", "command_injection"],
    "iis": ["path_traversal", "auth_bypass"],
    "graphql": ["sqli", "auth_bypass"],
    "mongodb": ["sqli", "auth_bypass"],
    "mysql": ["sqli"],
    "postgresql": ["sqli"],
    "redis": ["auth_bypass", "command_injection"],
    "docker": ["command_injection", "auth_bypass", "ssrf"],
    "kubernetes": ["ssrf", "auth_bypass", "command_injection"],
}


class VulnAnalyzer:
    """Analyzes recon findings and classifies them as vulnerabilities."""

    def analyze_mission(
        self,
        target: str,
        crawl_pages: list[dict[str, Any]],
        deep_probe_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Run full vulnerability analysis on mission results.

        Args:
            target: The target domain/URL
            crawl_pages: Pages from web_crawler.crawl()
            deep_probe_results: Results from deep_web_collector.probe()

        Returns:
            List of classified vulnerability findings
        """
        findings: list[dict[str, Any]] = []

        # 1. Classify deep web probe results
        for probe in deep_probe_results:
            probe_type = probe.get("type", "")
            mapped = PROBE_TYPE_TO_VULN.get(probe_type)
            if mapped:
                finding = {
                    "id": f"vuln-{uuid.uuid4().hex[:8]}",
                    "target": probe.get("url", target),
                    "vuln_class": mapped["vuln_class"],
                    "severity": mapped["severity"],
                    "description": f"{mapped['description']} [{probe_type}] at {probe.get('url', '')}",
                    "source": "deep_probe",
                    "probe_type": probe_type,
                    "exploit_hints": mapped.get("exploit_hints", {}),
                    "content": probe.get("interesting", ""),
                    "timestamp": datetime.now().isoformat(),
                }
                findings.append(finding)

        # 2. Scan crawl page content for vuln patterns
        seen_patterns: set[str] = set()
        for page in crawl_pages:
            url = page.get("url", "")
            content = page.get("content", "")
            tech_hints = page.get("tech_hints", [])

            # Content pattern matching
            for pattern_info in CONTENT_VULN_PATTERNS:
                if pattern_info["pattern"].search(content):
                    dedup_key = f"{url}:{pattern_info['vuln_class']}"
                    if dedup_key in seen_patterns:
                        continue
                    seen_patterns.add(dedup_key)

                    findings.append({
                        "id": f"vuln-{uuid.uuid4().hex[:8]}",
                        "target": url,
                        "vuln_class": pattern_info["vuln_class"],
                        "severity": pattern_info["severity"],
                        "description": f"{pattern_info['description']} at {url}",
                        "source": "content_scan",
                        "content": content[:500],
                        "timestamp": datetime.now().isoformat(),
                    })

            # 3. Check forms for injection points
            forms = page.get("forms", [])
            for form in forms:
                form_action = form.get("action", url)
                form_method = form.get("method", "GET")
                inputs = form.get("inputs", [])

                for inp in inputs:
                    inp_type = inp.get("type", "text")
                    inp_name = inp.get("name", "")
                    if inp_type in ("text", "search", "email", "url", "password", "hidden"):
                        # Auth forms → auth_bypass + sqli
                        if inp_type == "password" or "password" in inp_name.lower():
                            findings.append({
                                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                                "target": form_action,
                                "vuln_class": "auth_bypass",
                                "severity": "medium",
                                "description": f"Login form at {form_action} (field: {inp_name}) — test SQLi auth bypass",
                                "source": "form_analysis",
                                "exploit_hints": {"method": form_method, "field": inp_name},
                                "timestamp": datetime.now().isoformat(),
                            })
                            findings.append({
                                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                                "target": form_action,
                                "vuln_class": "sqli",
                                "severity": "medium",
                                "description": f"Input field '{inp_name}' in form at {form_action} — SQLi test target",
                                "source": "form_analysis",
                                "exploit_hints": {"method": form_method, "field": inp_name},
                                "timestamp": datetime.now().isoformat(),
                            })
                        else:
                            # Regular input → XSS + SQLi
                            findings.append({
                                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                                "target": form_action,
                                "vuln_class": "xss",
                                "severity": "low",
                                "description": f"Input field '{inp_name}' in form at {form_action} — XSS reflection test",
                                "source": "form_analysis",
                                "exploit_hints": {"method": form_method, "field": inp_name},
                                "timestamp": datetime.now().isoformat(),
                            })

            # 4. Tech stack → inferred vulnerabilities
            for tech in tech_hints:
                tech_lower = tech.lower()
                for tech_key, vuln_classes in TECH_TO_VULN.items():
                    if tech_key in tech_lower:
                        for vc in vuln_classes:
                            dedup_key = f"{url}:tech:{vc}"
                            if dedup_key in seen_patterns:
                                continue
                            seen_patterns.add(dedup_key)

                            # Lower severity for inferred (not confirmed) vulns
                            sev = "medium" if vc in ("sqli", "ssrf", "command_injection", "deserialization") else "low"
                            findings.append({
                                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                                "target": url,
                                "vuln_class": vc,
                                "severity": sev,
                                "description": f"Technology '{tech}' detected — {vc} is a common vulnerability class for this stack",
                                "source": "tech_inference",
                                "exploit_hints": {"tech": tech},
                                "timestamp": datetime.now().isoformat(),
                            })
                        break

        # 5. Active probing — test for common vulns even if nothing was found
        if not findings:
            findings.extend(self._generate_active_probes(target, crawl_pages))

        # Deduplicate by (target, vuln_class, source)
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for f in findings:
            key = f"{f['target']}:{f['vuln_class']}:{f.get('source', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _generate_active_probes(
        self, target: str, crawl_pages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Generate probe-based vulnerability findings when nothing was found passively.

        These are 'should test for' findings — the exploit engine will attempt
        non-destructive PoC validation against these.
        """
        findings: list[dict[str, Any]] = []
        base_url = target if target.startswith("http") else f"https://{target}"
        base_url = base_url.rstrip("/")

        # Always test for these on any web target
        baseline_tests = [
            {
                "vuln_class": "sqli",
                "severity": "medium",
                "description": f"Baseline SQLi probe — test all input parameters on {base_url}",
                "exploit_hints": {"paths": ["/?id=1", "/?q=test", "/api"]},
            },
            {
                "vuln_class": "xss",
                "severity": "low",
                "description": f"Baseline XSS probe — test reflection on {base_url}",
                "exploit_hints": {"paths": ["/?q=test", "/?search=test"]},
            },
            {
                "vuln_class": "auth_bypass",
                "severity": "medium",
                "description": f"Baseline auth bypass — test JWT alg=none and default creds on {base_url}",
                "exploit_hints": {"paths": ["/login", "/api/auth", "/admin"]},
            },
            {
                "vuln_class": "path_traversal",
                "severity": "medium",
                "description": f"Baseline path traversal — test LFI on {base_url}",
                "exploit_hints": {"paths": ["/?file=test", "/download?file=test"]},
            },
            {
                "vuln_class": "ssrf",
                "severity": "low",
                "description": f"Baseline SSRF — test URL parameters on {base_url}",
                "exploit_hints": {"paths": ["/?url=test", "/api/fetch?url=test"]},
            },
            {
                "vuln_class": "ssti",
                "severity": "low",
                "description": f"Baseline SSTI — test template injection on {base_url}",
                "exploit_hints": {"paths": ["/?name={{7*7}}", "/?template=test"]},
            },
            {
                "vuln_class": "command_injection",
                "severity": "low",
                "description": f"Baseline command injection — test OS command params on {base_url}",
                "exploit_hints": {"paths": ["/?cmd=test", "/?ping=test"]},
            },
        ]

        for bt in baseline_tests:
            findings.append({
                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                "target": base_url,
                "vuln_class": bt["vuln_class"],
                "severity": bt["severity"],
                "description": bt["description"],
                "source": "active_probe",
                "exploit_hints": bt.get("exploit_hints", {}),
                "timestamp": datetime.now().isoformat(),
            })

        return findings

    def store_findings(self, findings: list[dict[str, Any]]) -> int:
        """Store classified vulnerability findings in Neo4j.

        Stores as Memory nodes with exploit_class set so the exploit
        engine can find them via _get_target_findings().
        """
        stored = 0
        for finding in findings:
            try:
                finding_id = finding.get("id", f"vuln-{uuid.uuid4().hex[:8]}")
                cypher_write(
                    """
                    CREATE (m:Memory {
                      id: $id,
                      memory_type: 'episodic',
                      content: $content,
                      target: $target,
                      severity: $severity,
                      exploit_class: $vuln_class,
                      source: $source,
                      description: $description,
                      exploit_hints: $hints,
                      timestamp: datetime()
                    })
                    """,
                    {
                        "id": finding_id,
                        "content": finding.get("description", ""),
                        "target": finding.get("target", ""),
                        "severity": finding.get("severity", "info"),
                        "vuln_class": finding.get("vuln_class", ""),
                        "source": finding.get("source", ""),
                        "description": finding.get("description", ""),
                        "hints": str(finding.get("exploit_hints", {})),
                    },
                )
                stored += 1
            except Exception as e:
                logger.error(f"Failed to store vuln finding: {e}")

        logger.info(f"Stored {stored}/{len(findings)} vulnerability findings in Neo4j")
        return stored

    def analyze_existing_target(self, target: str) -> list[dict[str, Any]]:
        """Analyze an existing target by querying its stored memories and
        generating vulnerability findings from what's already in the graph.

        This is used when auto-exploit is called on a target that has recon
        data but no classified vulnerabilities yet.
        """
        # Get all memories for this target
        try:
            memories = cypher_read(
                """
                MATCH (m:Memory)
                WHERE m.target CONTAINS $target
                RETURN m.content AS content, m.severity AS severity,
                       m.exploit_class AS exploit_class, m.memory_type AS type
                ORDER BY m.timestamp DESC
                LIMIT 100
                """,
                {"target": target},
            )
        except Exception as e:
            logger.error(f"Failed to query existing memories for {target}: {e}")
            return []

        # Check if we already have classified vulns
        existing_vulns = [m for m in memories if m.get("exploit_class")]
        if existing_vulns:
            # Already have classified vulns, return them
            return [{
                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                "target": target,
                "vuln_class": m["exploit_class"],
                "severity": m.get("severity", "medium"),
                "description": m.get("content", ""),
                "source": "existing",
                "timestamp": datetime.now().isoformat(),
            } for m in existing_vulns]

        # Parse memories for tech hints and interesting content
        all_content = " ".join(m.get("content", "") for m in memories)
        tech_hints: list[str] = []
        for m in memories:
            content = m.get("content", "")
            # Extract tech from crawl memories
            if "tech=" in content:
                tech_part = content.split("tech=")[1].split(",")[0].strip()
                if tech_part:
                    for t in tech_part.split():
                        tech_hints.append(t.rstrip(")"))

        # Also get subdomains and pages from the graph
        try:
            subdomains = cypher_read(
                """
                MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE d.hostname CONTAINS $target
                RETURN s.name AS name
                LIMIT 20
                """,
                {"target": target},
            )
        except Exception:
            subdomains = []

        # Generate findings from existing data
        findings: list[dict[str, Any]] = []

        # Tech-inferred vulns
        seen: set[str] = set()
        for tech in tech_hints:
            tech_lower = tech.lower()
            for tech_key, vuln_classes in TECH_TO_VULN.items():
                if tech_key in tech_lower:
                    for vc in vuln_classes:
                        if vc not in seen:
                            seen.add(vc)
                            sev = "medium" if vc in ("sqli", "ssrf", "command_injection", "deserialization") else "low"
                            findings.append({
                                "id": f"vuln-{uuid.uuid4().hex[:8]}",
                                "target": target if target.startswith("http") else f"https://{target}",
                                "vuln_class": vc,
                                "severity": sev,
                                "description": f"Technology '{tech}' detected — {vc} is common for this stack",
                                "source": "tech_inference",
                                "exploit_hints": {"tech": tech},
                                "timestamp": datetime.now().isoformat(),
                            })
                    break

        # Content pattern scan on all stored content
        for pattern_info in CONTENT_VULN_PATTERNS:
            if pattern_info["pattern"].search(all_content):
                vc = pattern_info["vuln_class"]
                if vc not in seen:
                    seen.add(vc)
                    findings.append({
                        "id": f"vuln-{uuid.uuid4().hex[:8]}",
                        "target": target if target.startswith("http") else f"https://{target}",
                        "vuln_class": vc,
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                        "source": "content_scan",
                        "timestamp": datetime.now().isoformat(),
                    })

        # Always add baseline active probes
        base_url = target if target.startswith("http") else f"https://{target}"
        if not findings:
            findings = self._generate_active_probes(target, [])
        else:
            # Add baseline probes for vuln classes not already found
            existing_classes = {f["vuln_class"] for f in findings}
            for bt in self._generate_active_probes(target, []):
                if bt["vuln_class"] not in existing_classes:
                    findings.append(bt)

        return findings


# ── Singleton ──────────────────────────────────────────────────────

vuln_analyzer = VulnAnalyzer()