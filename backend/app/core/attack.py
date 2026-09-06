"""MITRE ATT&CK Framework Integration for PITBULL.

Loads ATT&CK techniques into Neo4j and maps exploration findings
to relevant ATT&CK techniques for threat-informed reconnaissance.

ATT&CK v19 (2026):
- 14 Tactics
- ~200 Techniques
- ~424 Sub-techniques
- Defense Evasion split into Stealth (TA0005) + Defense Impairment (TA0112)
- T1562 merged into T1685; new T1687 Exploitation for Defense Impairment
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import httpx

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)

# Core ATT&CK techniques most relevant to PITBULL exploration
# These are the techniques PITBULL can detect or that relate to its findings
ATTACK_TECHNIQUES = [
    # Reconnaissance (TA0043)
    {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance", "description": "Adversaries scan for vulnerabilities, open ports, services"},
    {"id": "T1595.001", "name": "Scanning IP Blocks", "tactic": "Reconnaissance", "description": "Scan IP address ranges for exposed services"},
    {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Reconnaissance", "description": "Scan for known vulnerabilities"},
    {"id": "T1592", "name": "Gather Victim Host Info", "tactic": "Reconnaissance", "description": "Collect info about target infrastructure"},
    {"id": "T1592.001", "name": "Hardware", "tactic": "Reconnaissance", "description": "Gather hardware info"},
    {"id": "T1592.002", "name": "Software", "tactic": "Reconnaissance", "description": "Gather software info — tech stack detection"},
    {"id": "T1592.004", "name": "Client Configurations", "tactic": "Reconnaissance", "description": "Gather client configuration info"},
    {"id": "T1589", "name": "Gather Victim Identity Info", "tactic": "Reconnaissance", "description": "Collect credentials, emails, user info"},
    {"id": "T1590", "name": "Gather Victim Network Info", "tactic": "Reconnaissance", "description": "Collect DNS, IP, domain info"},
    {"id": "T1590.001", "name": "Domain Properties", "tactic": "Reconnaissance", "description": "WHOIS, registration data"},
    {"id": "T1590.002", "name": "DNS", "tactic": "Reconnaissance", "description": "DNS records, subdomain enumeration"},
    {"id": "T1590.003", "name": "Network Trust Dependencies", "tactic": "Reconnaissance", "description": "Map network relationships"},
    {"id": "T1590.005", "name": "IP Addresses", "tactic": "Reconnaissance", "description": "Collect target IP addresses"},
    {"id": "T1590.006", "name": "Network Security Devices", "tactic": "Reconnaissance", "description": "Identify WAF, IDS, firewalls"},
    {"id": "T1591", "name": "Gather Victim Org Info", "tactic": "Reconnaissance", "description": "Collect organizational info"},
    {"id": "T1591.001", "name": "Determine Physical Locations", "tactic": "Reconnaissance", "description": "Geographic location of infrastructure"},
    {"id": "T1591.002", "name": "Business Relationships", "tactic": "Reconnaissance", "description": "Identify business partnerships"},
    {"id": "T1591.004", "name": "Identify Roles", "tactic": "Reconnaissance", "description": "Map personnel roles"},
    {"id": "T1586", "name": "Compromise Infrastructure", "tactic": "Resource Development", "description": "Compromise infrastructure for use"},
    {"id": "T1583", "name": "Acquire Infrastructure", "tactic": "Resource Development", "description": "Acquire infrastructure for operations"},

    # Initial Access (TA0001)
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Exploit vulnerabilities in internet-facing apps"},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "description": "Use legitimate credentials"},
    {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access", "description": "Exploit exposed remote services"},
    {"id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access", "description": "Compromise via supplier"},
    {"id": "T1199", "name": "Trusted Relationship", "tactic": "Initial Access", "description": "Exploit trusted business relationships"},

    # Credential Access (TA0006)
    {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access", "description": "Find credentials in files, logs, etc."},
    {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access", "description": "Credentials stored in .env, config files"},
    {"id": "T1552.003", "name": "Bash History", "tactic": "Credential Access", "description": "Credentials in bash history"},
    {"id": "T1552.004", "name": "Private Keys", "tactic": "Credential Access", "description": "Private keys found in repositories or files"},
    {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access", "description": "Extract from password managers"},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "description": "Password guessing"},
    {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access", "description": "Guess passwords"},
    {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access", "description": "Spray passwords across accounts"},

    # Discovery (TA0007)
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "description": "Scan for network services"},
    {"id": "T1046.001", "name": "Network Service Scanning", "tactic": "Discovery", "description": "Port scanning"},
    {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery", "description": "Find user accounts"},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "description": "Enumerate files and directories"},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "description": "Gather system info"},
    {"id": "T1010", "name": "Application Window Discovery", "tactic": "Discovery", "description": "Find running applications"},

    # Defense Evasion — Stealth (TA0005)
    {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion", "description": "Disable or impair security tools"},
    {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion", "description": "Disable security tools"},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "description": "Obfuscate to avoid detection"},
    {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion", "description": "Disguise as legitimate"},
    {"id": "T1036.005", "name": "Match Legitimate Name", "tactic": "Defense Evasion", "description": "Match name of legitimate process/file"},

    # Defense Impairment (TA0112) — new in v19
    {"id": "T1685", "name": "Impair Defenses", "tactic": "Defense Impairment", "description": "Merged T1562 — actively impair defense mechanisms"},
    {"id": "T1687", "name": "Exploitation for Defense Impairment", "tactic": "Defense Impairment", "description": "Exploit vulnerabilities to impair defenses"},

    # Command and Control (TA0011)
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Use standard protocols for C2"},
    {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control", "description": "Use HTTP/HTTPS for C2"},
    {"id": "T1090", "name": "Proxy", "tactic": "Command and Control", "description": "Use proxy to relay traffic"},
    {"id": "T1090.001", "name": "Internal Proxy", "tactic": "Command and Control", "description": "Use internal proxy"},
    {"id": "T1090.003", "name": "Multi-hop Proxy", "tactic": "Command and Control", "description": "Chain multiple proxies"},
    {"id": "T1090.004", "name": "Domain Fronting", "tactic": "Command and Control", "description": "Use CDN for fronting"},
    {"id": "T1132", "name": "Data Encoding", "tactic": "Command and Control", "description": "Encode data to hide it"},
    {"id": "T1008", "name": "Fallback Channels", "tactic": "Command and Control", "description": "Use backup C2 channels"},

    # Exfiltration (TA0010)
    {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "description": "Send data via web services"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Send data through C2"},
    {"id": "T1052", "name": "Exfiltration Over Physical Medium", "tactic": "Exfiltration", "description": "USB, physical transfer"},

    # Collection (TA0009)
    {"id": "T1213", "name": "Data from Information Repositories", "tactic": "Collection", "description": "Access data from repos"},
    {"id": "T1213.001", "name": "Confluence", "tactic": "Collection", "description": "Access Confluence"},
    {"id": "T1213.003", "name": "Code Repositories", "tactic": "Collection", "description": "Access code repos — GitHub recon"},
    {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Collection", "description": "Intercept traffic"},

    # Lateral Movement (TA0008)
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "description": "Use remote services"},
    {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement", "description": "RDP"},
    {"id": "T1021.004", "name": "SSH", "tactic": "Lateral Movement", "description": "SSH"},
    {"id": "T1021.006", "name": "Windows Remote Management", "tactic": "Lateral Movement", "description": "WinRM"},
    {"id": "T1072", "name": "Software Deployment Tools", "tactic": "Lateral Movement", "description": "Use deployment tools"},

    # Impact (TA0040)
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Ransomware"},
    {"id": "T1485", "name": "Data Destruction", "tactic": "Impact", "description": "Destroy data"},
    {"id": "T1561", "name": "Disk Wipe", "tactic": "Impact", "description": "Wipe disks"},
    {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact", "description": "DoS"},

    # Credential Access via OSINT
    {"id": "T1589.001", "name": "Credentials", "tactic": "Reconnaissance", "description": "Gather credentials via OSINT"},
    {"id": "T1589.002", "name": "Email Addresses", "tactic": "Reconnaissance", "description": "Collect email addresses"},
    {"id": "T1596", "name": "Search Open Technical Databases", "tactic": "Reconnaissance", "description": "Search Shodan, Censys, etc."},
    {"id": "T1596.001", "name": "Search Engines", "tactic": "Reconnaissance", "description": "Use search engines for recon"},
    {"id": "T1596.002", "name": "Search Open Databases", "tactic": "Reconnaissance", "description": "Search open databases"},
    {"id": "T1596.003", "name": "Code Repositories", "tactic": "Reconnaissance", "description": "Search GitHub for leaked info"},
    {"id": "T1596.004", "name": "Social Media", "tactic": "Reconnaissance", "description": "Search social media"},
    {"id": "T1596.005", "name": "Scanning Databases", "tactic": "Reconnaissance", "description": "Search Shodan/Censys"},
]


class AttackFramework:
    """MITRE ATT&CK framework integration for PITBULL."""

    def load_into_neo4j(self) -> dict[str, Any]:
        """Load all ATT&CK techniques into Neo4j."""
        loaded = 0
        for tech in ATTACK_TECHNIQUES:
            cypher_write(
                "MERGE (t:ATTACKTechnique {id: $id}) "
                "SET t.name = $name, t.tactic = $tactic, "
                "t.description = $desc, t.loaded_at = datetime()",
                {
                    "id": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "desc": tech["description"],
                },
            )
            loaded += 1

        logger.info(f"Loaded {loaded} ATT&CK techniques into Neo4j")
        return {"loaded": loaded, "total": len(ATTACK_TECHNIQUES)}

    def map_finding_to_technique(self, finding_type: str, finding_content: str) -> list[dict[str, Any]]:
        """Map an PITBULL finding to relevant ATT&CK techniques."""
        content_lower = finding_content.lower()
        mappings = []

        # DNS recon → T1590.002
        if "dns" in content_lower or "subdomain" in content_lower:
            mappings.append({"technique": "T1590.002", "name": "DNS", "tactic": "Reconnaissance", "confidence": 0.9})

        # WHOIS → T1590.001
        if "whois" in content_lower or "registrar" in content_lower:
            mappings.append({"technique": "T1590.001", "name": "Domain Properties", "tactic": "Reconnaissance", "confidence": 0.9})

        # IP resolution → T1590.005
        if "ip" in content_lower and "resolv" in content_lower:
            mappings.append({"technique": "T1590.005", "name": "IP Addresses", "tactic": "Reconnaissance", "confidence": 0.85})

        # Tech stack detection → T1592.002
        if "tech" in content_lower or "technology" in content_lower:
            mappings.append({"technique": "T1592.002", "name": "Software", "tactic": "Reconnaissance", "confidence": 0.85})

        # Certificate transparency → T1590.001
        if "certificate" in content_lower or "cert" in content_lower:
            mappings.append({"technique": "T1590.001", "name": "Domain Properties", "tactic": "Reconnaissance", "confidence": 0.7})

        # Shodan → T1596.005
        if "shodan" in content_lower:
            mappings.append({"technique": "T1596.005", "name": "Scanning Databases", "tactic": "Reconnaissance", "confidence": 0.95})

        # GitHub recon → T1596.003
        if "github" in content_lower:
            mappings.append({"technique": "T1596.003", "name": "Code Repositories", "tactic": "Reconnaissance", "confidence": 0.95})

        # Wayback → T1596.001
        if "wayback" in content_lower or "archive" in content_lower:
            mappings.append({"technique": "T1596.001", "name": "Search Engines", "tactic": "Reconnaissance", "confidence": 0.8})

        # Exposed .env / config → T1552.001
        if ".env" in content_lower or "config" in content_lower and "exposed" in content_lower:
            mappings.append({"technique": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access", "confidence": 0.8})

        # Exposed .git → T1552.004 (private keys) or T1213.003 (code repos)
        if ".git" in content_lower:
            mappings.append({"technique": "T1213.003", "name": "Code Repositories", "tactic": "Collection", "confidence": 0.85})
            mappings.append({"technique": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access", "confidence": 0.6})

        # Admin panel → T1190
        if "admin" in content_lower and ("panel" in content_lower or "exposed" in content_lower):
            mappings.append({"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.7})

        # API endpoint → T1190
        if "api" in content_lower and ("endpoint" in content_lower or "swagger" in content_lower or "openapi" in content_lower):
            mappings.append({"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.6})

        # GraphQL → T1190
        if "graphql" in content_lower:
            mappings.append({"technique": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.65})

        # Tor / darknet → T1090 (Proxy)
        if "tor" in content_lower or "onion" in content_lower:
            mappings.append({"technique": "T1090", "name": "Proxy", "tactic": "Command and Control", "confidence": 0.7})
            mappings.append({"technique": "T1090.003", "name": "Multi-hop Proxy", "tactic": "Command and Control", "confidence": 0.8})

        # Deep probe / port scan → T1595
        if "deep probe" in content_lower or "port" in content_lower:
            mappings.append({"technique": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance", "confidence": 0.85})
            mappings.append({"technique": "T1595.001", "name": "Scanning IP Blocks", "tactic": "Reconnaissance", "confidence": 0.7})

        # WAF / security device → T1590.006
        if "waf" in content_lower or "cloudflare" in content_lower and "protect" in content_lower:
            mappings.append({"technique": "T1590.006", "name": "Network Security Devices", "tactic": "Reconnaissance", "confidence": 0.7})

        return mappings

    def map_mission_findings(self, target: str) -> dict[str, Any]:
        """Map all findings from a mission to ATT&CK techniques."""
        memories = cypher_read(
            "MATCH (m:Memory) WHERE m.target CONTAINS $target AND m.content IS NOT NULL "
            "RETURN m.content AS content, m.memory_type AS type, m.severity AS severity "
            "ORDER BY m.timestamp DESC LIMIT 200",
            {"target": target},
        )

        all_mappings: dict[str, dict] = {}  # technique_id -> {info, count, findings}

        for entry in memories:
            content = entry.get("content", "")
            mtype = entry.get("type", "")
            mappings = self.map_finding_to_technique(mtype, content)

            for mapping in mappings:
                tech_id = mapping["technique"]
                if tech_id not in all_mappings:
                    all_mappings[tech_id] = {
                        "technique": tech_id,
                        "name": mapping["name"],
                        "tactic": mapping["tactic"],
                        "confidence": mapping["confidence"],
                        "finding_count": 0,
                        "findings": [],
                    }
                all_mappings[tech_id]["finding_count"] += 1
                all_mappings[tech_id]["findings"].append(content[:100])

        # Store mappings in Neo4j
        for tech_id, data in all_mappings.items():
            cypher_write(
                "MERGE (t:ATTACKTechnique {id: $tech_id}) "
                "MERGE (d:Domain {hostname: $target}) "
                "MERGE (d)-[:DETECTED_USING]->(t) "
                "SET t.last_mapped = datetime(), t.finding_count = $count",
                {
                    "tech_id": tech_id,
                    "target": target,
                    "count": data["finding_count"],
                },
            )

        # Sort by finding count
        sorted_mappings = sorted(all_mappings.values(), key=lambda x: x["finding_count"], reverse=True)

        tactics_covered = list(set(m["tactic"] for m in sorted_mappings))
        techniques_covered = len(sorted_mappings)

        return {
            "target": target,
            "techniques_mapped": techniques_covered,
            "tactics_covered": tactics_covered,
            "tactic_count": len(tactics_covered),
            "mappings": sorted_mappings,
        }

    def get_techniques(self, tactic: str | None = None) -> list[dict[str, Any]]:
        """Get ATT&CK techniques from Neo4j."""
        if tactic:
            results = cypher_read(
                "MATCH (t:ATTACKTechnique {tactic: $tactic}) RETURN t ORDER BY t.id",
                {"tactic": tactic},
            )
        else:
            results = cypher_read("MATCH (t:ATTACKTechnique) RETURN t ORDER BY t.tactic, t.id")

        return [
            {
                "id": r.get("t", {}).get("id", ""),
                "name": r.get("t", {}).get("name", ""),
                "tactic": r.get("t", {}).get("tactic", ""),
                "description": r.get("t", {}).get("description", ""),
            }
            for r in results
        ]

    def get_coverage(self, target: str) -> dict[str, Any]:
        """Get ATT&CK coverage for a target."""
        coverage = cypher_read(
            "MATCH (d:Domain {hostname: $target})-[:DETECTED_USING]->(t:ATTACKTechnique) "
            "RETURN t.id AS tech_id, t.name AS name, t.tactic AS tactic, "
            "t.finding_count AS findings ORDER BY t.tactic, t.id",
            {"target": target},
        )

        tactics: dict[str, list] = {}
        for r in coverage:
            tactic = r.get("tactic", "Unknown")
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append({
                "id": r.get("tech_id", ""),
                "name": r.get("name", ""),
                "findings": r.get("findings", 0),
            })

        return {
            "target": target,
            "total_techniques": sum(len(t) for t in tactics.values()),
            "tactics": tactics,
            "tactic_count": len(tactics),
        }

    def get_stats(self) -> dict[str, Any]:
        """Get ATT&CK framework statistics."""
        total = cypher_read("MATCH (t:ATTACKTechnique) RETURN count(t) AS count")
        tactics = cypher_read(
            "MATCH (t:ATTACKTechnique) RETURN t.tactic AS tactic, count(t) AS count ORDER BY count DESC"
        )
        mapped = cypher_read(
            "MATCH (d:Domain)-[:DETECTED_USING]->(t:ATTACKTechnique) "
            "RETURN count(DISTINCT t) AS mapped_techniques, count(DISTINCT d) AS mapped_domains"
        )

        return {
            "total_techniques": total[0]["count"] if total else 0,
            "by_tactic": {r.get("tactic", "?"): r.get("count", 0) for r in tactics},
            "mapped_techniques": mapped[0].get("mapped_techniques", 0) if mapped else 0,
            "mapped_domains": mapped[0].get("mapped_domains", 0) if mapped else 0,
        }


attack_framework = AttackFramework()