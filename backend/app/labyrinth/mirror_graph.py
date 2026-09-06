"""MirrorGraph Engine — generates and maintains a fabricated parallel infrastructure.

The MirrorGraph is an ontologically consistent fake network. Every domain resolves,
every IP responds, every port runs a plausible service, every CVE matches the
service version. The attacker cannot find a crack because the ontology enforces
consistency.

This module:
- Clones the TrueGraph's structure (object types, relationship types)
- Replaces sensitive values with fabricated-but-consistent alternatives
- Generates plausible fake vulnerabilities, credentials, persons
- Tags every MirrorGraph node with `__mirror__: true` for internal tracking
- Ensures cross-references between MirrorGraph nodes are internally consistent

Uses PITBULL's cypher_write/cypher_read for all Neo4j operations.

Academic basis:
- Polad et al. 2019: fake vulnerabilities in attack graphs maximize attacker cost
- Kulkarni & Fu 2020: hypergame theory requires asymmetric information via decoys
- Palantir ontology: objects → properties → relationships must be internally consistent
"""

from __future__ import annotations

import logging
import random
import secrets
random.seed(secrets.randbelow(2**32))
import uuid
from datetime import datetime, date, timedelta, timezone
from typing import Any, Optional

from app.core.database import cypher_write, cypher_read
from app.labyrinth.consistency_validator import PORT_SERVICE_MAP, ObjectType, LinkType

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
#  FABRICATION DATA — plausible fake values
# ═══════════════════════════════════════════════════════════════════════

# Documentation/reserved IP ranges (RFC 5737) — safe to use in fake infra
FAKE_IP_POOL = [
    "203.0.113.{}",  # TEST-NET-3
    "198.51.100.{}",  # TEST-NET-2
    "192.0.2.{}",  # TEST-NET-1
]

# Plausible service versions (slightly outdated but real)
SERVICE_TEMPLATES = [
    {"name": "nginx", "version": "1.24.0", "cpe": "cpe:2.3:a:nginx:nginx:1.24.0", "ports": [80, 443]},
    {"name": "nginx", "version": "1.22.1", "cpe": "cpe:2.3:a:nginx:nginx:1.22.1", "ports": [80, 443]},
    {"name": "Apache httpd", "version": "2.4.58", "cpe": "cpe:2.3:a:apache:http_server:2.4.58", "ports": [80, 443, 8080]},
    {"name": "OpenSSH", "version": "9.3p1", "cpe": "cpe:2.3:a:openssh:openssh:9.3p1", "ports": [22]},
    {"name": "OpenSSH", "version": "8.9p1", "cpe": "cpe:2.3:a:openssh:openssh:8.9p1", "ports": [22]},
    {"name": "MySQL", "version": "8.0.35", "cpe": "cpe:2.3:a:oracle:mysql:8.0.35", "ports": [3306]},
    {"name": "PostgreSQL", "version": "15.4", "cpe": "cpe:2.3:a:postgresql:postgresql:15.4", "ports": [5432]},
    {"name": "Redis", "version": "7.2.3", "cpe": "cpe:2.3:a:redis:redis:7.2.3", "ports": [6379]},
    {"name": "Apache Tomcat", "version": "9.0.82", "cpe": "cpe:2.3:a:apache:tomcat:9.0.82", "ports": [8080, 8443]},
    {"name": "Node.js Express", "version": "4.18.2", "cpe": "cpe:2.3:a:nodejs:express:4.18.2", "ports": [3000, 8080]},
    {"name": "Docker Registry", "version": "2.8.2", "cpe": "cpe:2.3:a:docker:registry:2.8.2", "ports": [5000]},
    {"name": "Elasticsearch", "version": "8.11.0", "cpe": "cpe:2.3:a:elastic:elasticsearch:8.11.0", "ports": [9200, 9300]},
    {"name": "Kibana", "version": "8.11.0", "cpe": "cpe:2.3:a:elastic:kibana:8.11.0", "ports": [5601]},
    {"name": "MongoDB", "version": "7.0.5", "cpe": "cpe:2.3:a:mongodb:mongodb:7.0.5", "ports": [27017]},
    {"name": "Grafana", "version": "10.2.0", "cpe": "cpe:2.3:a:grafana:grafana:10.2.0", "ports": [3000]},
    {"name": "Jenkins", "version": "2.426.1", "cpe": "cpe:2.3:a:jenkins:jenkins:2.426.1", "ports": [8080, 50000]},
    {"name": "GitLab CE", "version": "16.6.0", "cpe": "cpe:2.3:a:gitlab:gitlab:16.6.0", "ports": [80, 443, 22]},
    {"name": "WordPress", "version": "6.4.1", "cpe": "cpe:2.3:a:wordpress:wordpress:6.4.1", "ports": [80, 443]},
    {"name": "phpMyAdmin", "version": "5.2.1", "cpe": "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1", "ports": [80, 443]},
    {"name": "RabbitMQ", "version": "3.12.8", "cpe": "cpe:2.3:a:vmware:rabbitmq:3.12.8", "ports": [5672, 15672]},
]

# Real CVEs that match the service templates above — ensures consistency
CVE_TEMPLATES = {
    "nginx": [
        {"cve_id": "CVE-2024-7347", "description": "nginx HTTP/3 QUIC denial of service", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": True},
        {"cve_id": "CVE-2023-44487", "description": "HTTP/2 Rapid Reset Attack", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": True},
    ],
    "Apache httpd": [
        {"cve_id": "CVE-2023-45802", "description": "Apache HTTP Server: HTTP/2 stream memory leak", "cvss_v3_score": 5.3, "severity": "MEDIUM", "exploit_available": False},
        {"cve_id": "CVE-2023-31122", "description": "Apache HTTP Server: mod_status DoS", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": True},
    ],
    "OpenSSH": [
        {"cve_id": "CVE-2023-38408", "description": "OpenSSH ssh-agent RCE via PKCS#11", "cvss_v3_score": 9.8, "severity": "CRITICAL", "exploit_available": True},
        {"cve_id": "CVE-2023-48795", "description": "Terrapin Attack — SSH protocol prefix truncation", "cvss_v3_score": 5.9, "severity": "MEDIUM", "exploit_available": False},
    ],
    "MySQL": [
        {"cve_id": "CVE-2023-22084", "description": "MySQL Server: InnoDB DoS", "cvss_v3_score": 4.9, "severity": "MEDIUM", "exploit_available": False},
        {"cve_id": "CVE-2023-22007", "description": "MySQL Server: Server: Replication RCE", "cvss_v3_score": 7.4, "severity": "HIGH", "exploit_available": True},
    ],
    "PostgreSQL": [
        {"cve_id": "CVE-2023-39417", "description": "PostgreSQL extension script RCE", "cvss_v3_score": 8.8, "severity": "HIGH", "exploit_available": True},
        {"cve_id": "CVE-2023-5868", "description": "PostgreSQL aggregate function overflow", "cvss_v3_score": 7.8, "severity": "HIGH", "exploit_available": False},
    ],
    "Redis": [
        {"cve_id": "CVE-2023-41053", "description": "Redis Lua sandbox escape via cjson", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": True},
        {"cve_id": "CVE-2023-28856", "description": "Redis HRANDFIELD/ZRANDMEMBER OOM", "cvss_v3_score": 5.5, "severity": "MEDIUM", "exploit_available": False},
    ],
    "Apache Tomcat": [
        {"cve_id": "CVE-2023-46589", "description": "Apache Tomcat: HTTP/2 RST flood DoS", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": True},
        {"cve_id": "CVE-2023-42794", "description": "Apache Tomcat: recycled request smuggling", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": True},
    ],
    "Jenkins": [
        {"cve_id": "CVE-2023-41931", "description": "Jenkins CSRF token bypass", "cvss_v3_score": 8.8, "severity": "HIGH", "exploit_available": True},
        {"cve_id": "CVE-2024-23897", "description": "Jenkins arbitrary file read via CLI", "cvss_v3_score": 9.8, "severity": "CRITICAL", "exploit_available": True},
    ],
    "GitLab CE": [
        {"cve_id": "CVE-2023-7028", "description": "GitLab account takeover via send email reset", "cvss_v3_score": 10.0, "severity": "CRITICAL", "exploit_available": True},
        {"cve_id": "CVE-2023-4839", "description": "GitLab SSRF via Jira integration", "cvss_v3_score": 8.8, "severity": "HIGH", "exploit_available": True},
    ],
    "WordPress": [
        {"cve_id": "CVE-2023-2745", "description": "WordPress directory traversal in attachment pages", "cvss_v3_score": 6.5, "severity": "MEDIUM", "exploit_available": False},
        {"cve_id": "CVE-2023-3460", "description": "WordPress privilege escalation via user meta", "cvss_v3_score": 9.8, "severity": "CRITICAL", "exploit_available": True},
    ],
    "MongoDB": [
        {"cve_id": "CVE-2023-1409", "description": "MongoDB BSON deserialization DoS", "cvss_v3_score": 6.5, "severity": "MEDIUM", "exploit_available": False},
    ],
    "Elasticsearch": [
        {"cve_id": "CVE-2023-31413", "description": "Elasticsearch sandbox escape via Groovy", "cvss_v3_score": 9.9, "severity": "CRITICAL", "exploit_available": True},
    ],
    "Grafana": [
        {"cve_id": "CVE-2023-6152", "description": "Grafana: stored XSS in data source proxy", "cvss_v3_score": 6.1, "severity": "MEDIUM", "exploit_available": True},
    ],
    "Kibana": [
        {"cve_id": "CVE-2023-31415", "description": "Kibana: prototype pollution RCE", "cvss_v3_score": 9.9, "severity": "CRITICAL", "exploit_available": True},
    ],
    "phpMyAdmin": [
        {"cve_id": "CVE-2023-25054", "description": "phpMyAdmin SQL injection in transformation", "cvss_v3_score": 8.6, "severity": "HIGH", "exploit_available": True},
    ],
    "RabbitMQ": [
        {"cve_id": "CVE-2023-46120", "description": "RabbitMQ: MQTT parser DoS", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": False},
    ],
    "Node.js Express": [
        {"cve_id": "CVE-2023-26136", "description": "Express.js: prototype pollution via body parsing", "cvss_v3_score": 7.5, "severity": "HIGH", "exploit_available": True},
    ],
    "Docker Registry": [
        {"cve_id": "CVE-2023-2253", "description": "Docker Registry: authentication bypass", "cvss_v3_score": 9.1, "severity": "CRITICAL", "exploit_available": True},
    ],
}

# Fake person name components
FIRST_NAMES = ["James", "Sarah", "Michael", "Emma", "David", "Lisa", "Robert", "Anna", "Daniel", "Sophie",
               "Marcus", "Elena", "Thomas", "Rachel", "Andrew", "Natalie", "Christopher", "Victoria", "Jonathan", "Priya"]
LAST_NAMES = ["Mitchell", "Chen", "Kowalski", "Santos", "Foster", "Reyes", "Bennett", "Sharma", "Walker", "Costa",
              "Hughes", "Romero", "Rossi", "Kelly", "Patel", "Nguyen", "Andersson", "Silva", "Khan", "Müller"]
ROLES = ["CTO", "DevOps Lead", "SysAdmin", "Security Analyst", "Senior Developer", "DevOps Engineer", "Platform Engineer", "Site Reliability Engineer", "Backend Developer", "IT Manager"]

# Fake domain prefixes
SUBDOMAIN_PREFIXES = ["api", "portal", "admin", "vpn", "mail", "git", "ci", "staging", "dev", "internal",
                      "monitor", "grafana", "jenkins", "registry", "docs", "wiki", "chat", "status", "auth", "cloud"]

# Fake registrars
REGISTRARS = ["GoDaddy", "Namecheap", "123-Reg", "Cloudflare", "Google Domains", "Gandi", "Name.com", "Hover"]

# Fake industries
INDUSTRIES = ["Technology", "Healthcare", "Financial Services", "E-commerce", "Media", "Education", "Manufacturing", "Logistics"]

# Fake breach databases
BREACH_SOURCES = ["Collection #1", "BreachForums", "DeHashed", "LeakCheck", "HIBP", "snusbase"]

# ATT&CK techniques commonly associated with exploitation
ATTACK_TECHNIQUE_POOL = [
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    {"technique_id": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
    {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"technique_id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"technique_id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
    {"technique_id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    {"technique_id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    {"technique_id": "T1021.004", "name": "SSH", "tactic": "Lateral Movement"},
    {"technique_id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
    {"technique_id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    {"technique_id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution"},
    {"technique_id": "T1090", "name": "Proxy", "tactic": "Command and Control"},
    {"technique_id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
]

# Merge key per object type — used for MERGE in Neo4j
_MERGE_KEYS = {
    ObjectType.ORGANIZATION: "name",
    ObjectType.DOMAIN: "hostname",
    ObjectType.SUBDOMAIN: "name",
    ObjectType.IP_ADDRESS: "ip",
    ObjectType.CVE: "cve_id",
    ObjectType.ATTCK_TECHNIQUE: "technique_id",
    ObjectType.PERSON: "email",
}


class MirrorGraphEngine:
    """Generates and manages the fabricated MirrorGraph.

    The MirrorGraph is stored in the same Neo4j database as the TrueGraph,
    but every MirrorGraph node has `__mirror__: true` to distinguish it.
    """

    def __init__(self) -> None:
        self._ip_counter = 10  # start at .10 for each /24
        self._generated: dict[str, str] = {}  # true_id → mirror_id mapping
        self._mirror_nodes: dict[str, dict] = {}  # mirror_id → node props
        self._mirror_rels: list[tuple[str, str, str]] = []  # (source_mirror_id, target_mirror_id, link_type)

    # ── PUBLIC API ────────────────────────────────────────────────────

    def generate_mirror(self, scale: float = 1.0) -> dict[str, Any]:
        """Generate the MirrorGraph from the current TrueGraph.

        Args:
            scale: Multiplier for how many fakes to generate per real node.
                   1.0 = 1:1 mirror, 1.5 = 50% more fakes than reals, etc.

        Returns:
            Summary statistics of what was generated.
        """
        logger.info("EPHEMERAL LABYRINTH: Starting MirrorGraph generation (scale=%.1f)", scale)

        # Fetch the TrueGraph using PITBULL's cypher_read
        true_nodes = cypher_read(
            "MATCH (n) WHERE NOT n:MirrorNode "
            "RETURN n.id AS id, labels(n) AS labels, properties(n) AS props "
            "LIMIT 5000"
        )
        true_edges = cypher_read(
            "MATCH (a)-[r]->(b) WHERE NOT a:MirrorNode AND NOT b:MirrorNode "
            "RETURN a.id AS source_id, b.id AS target_id, type(r) AS rel_type, properties(r) AS props"
        )

        if not true_nodes:
            logger.warning("EPHEMERAL LABYRINTH: TrueGraph is empty — nothing to mirror")
            return {"error": "TrueGraph is empty", "mirror_nodes": 0, "mirror_rels": 0}

        logger.info("EPHEMERAL LABYRINTH: TrueGraph has %d nodes, %d edges", len(true_nodes), len(true_edges))

        # Clear any existing MirrorGraph nodes
        self._clear_mirror()

        # Build port→service_id mapping from TrueGraph RUNS edges
        port_for_service: dict[str, int] = {}
        for edge in true_edges:
            if edge.get("rel_type") == LinkType.RUNS:
                src_id = edge.get("source_id", "")
                tgt_id = edge.get("target_id", "")
                for n in true_nodes:
                    nprops = self._get_props(n)
                    if nprops.get("id") == src_id:
                        pn = nprops.get("port_number")
                        if pn:
                            port_for_service[tgt_id] = int(pn)
                        break

        # Build cve→service_name mapping from TrueGraph VULNERABLE_TO edges
        service_for_cve: dict[str, str] = {}
        for edge in true_edges:
            if edge.get("rel_type") == LinkType.VULNERABLE_TO:
                svc_id = edge.get("source_id", "")
                cve_id = edge.get("target_id", "")
                for n in true_nodes:
                    nprops = self._get_props(n)
                    if nprops.get("id") == svc_id:
                        service_for_cve[cve_id] = nprops.get("name", "")
                        break

        logger.info("EPHEMERAL LABYRINTH: Built port→service map (%d), cve→service map (%d)",
                    len(port_for_service), len(service_for_cve))

        # Generate mirror nodes for each real node
        stats = {"organizations": 0, "domains": 0, "subdomains": 0, "ips": 0,
                 "ports": 0, "services": 0, "cves": 0, "persons": 0, "credentials": 0,
                 "certificates": 0, "techniques": 0}

        for true_node in true_nodes:
            obj_type = self._get_type(true_node)
            props = self._get_props(true_node)
            true_id = props.get("id", "")

            if not obj_type or not true_id:
                continue

            # Skip ATTCKTechnique — those are real MITRE data, reuse them
            if obj_type == ObjectType.ATTCK_TECHNIQUE:
                self._generated[true_id] = true_id  # point to real node
                stats["techniques"] += 1
                continue

            # Inject port number into service props for port-aware fabrication
            if obj_type == ObjectType.SERVICE and true_id in port_for_service:
                props = {**props, "_port_number": port_for_service[true_id]}

            # Inject service name into CVE props for service-aware fabrication
            if obj_type == ObjectType.CVE and true_id in service_for_cve:
                props = {**props, "_service_name": service_for_cve[true_id]}

            # Generate the mirror version
            mirror_props = self._fabricate_node(obj_type, props, scale)
            if mirror_props:
                mirror_id = self._create_mirror_node(obj_type, mirror_props)
                if mirror_id:
                    self._generated[true_id] = mirror_id
                    self._mirror_nodes[mirror_id] = mirror_props
                    type_key = obj_type.lower() + "s"
                    if type_key in stats:
                        stats[type_key] += 1

        logger.info("EPHEMERAL LABYRINTH: Generated %d mirror nodes", len(self._mirror_nodes))

        # Generate mirror relationships (mapped from true relationships)
        for edge in true_edges:
            src_true = edge.get("source_id", "")
            tgt_true = edge.get("target_id", "")
            rel_type = edge.get("rel_type", "")

            src_mirror = self._generated.get(src_true)
            tgt_mirror = self._generated.get(tgt_true)

            if src_mirror and tgt_mirror and rel_type:
                self._create_mirror_rel(src_mirror, tgt_mirror, rel_type)
                self._mirror_rels.append((src_mirror, tgt_mirror, rel_type))

        logger.info("EPHEMERAL LABYRINTH: Generated %d mirror relationships", len(self._mirror_rels))

        # Generate ADDITIONAL fake-only nodes (extra deception layer)
        extra = self._generate_extras(scale)
        for k, v in extra.items():
            stats[k] = stats.get(k, 0) + v

        stats["mirror_nodes_total"] = len(self._mirror_nodes)
        stats["mirror_rels_total"] = len(self._mirror_rels)
        stats["scale"] = scale

        logger.info("EPHEMERAL LABYRINTH: MirrorGraph generation complete — %d nodes, %d relationships",
                    stats["mirror_nodes_total"], stats["mirror_rels_total"])

        return stats

    def generate_synthetic(self, scale: float = 1.0) -> dict[str, Any]:
        """Generate a fully synthetic MirrorGraph from scratch.

        When the TrueGraph is empty (no pipeline scans have been run yet),
        this method creates a plausible fake infrastructure entirely from
        the built-in templates. The result is a complete ontology-consistent
        network: Organization → Domains → Subdomains → IPs → Ports →
        Services → CVEs → ATT&CK Techniques, plus Persons, Credentials,
        and Certificates.

        Args:
            scale: Controls how large the synthetic infra is.
                   1.0 = 1 org, 2 domains, 4 subdomains, 3 IPs, ~10 services
                   2.0 = 2 orgs, 4 domains, 8 subdomains, 6 IPs, ~20 services

        Returns:
            Summary statistics of what was generated.
        """
        logger.info("EPHEMERAL LABYRINTH: Starting SYNTHETIC generation (scale=%.1f) — no TrueGraph data", scale)

        # Clear any existing MirrorGraph nodes
        self._clear_mirror()

        stats: dict[str, int] = {
            "organizations": 0, "domains": 0, "subdomains": 0,
            "ips": 0, "ports": 0, "services": 0, "cves": 0,
            "persons": 0, "credentials": 0, "certificates": 0, "techniques": 0,
        }

        n_orgs = max(1, int(scale))
        n_domains_per_org = max(1, int(2 * scale))
        n_subdomains_per_domain = max(2, int(4 * scale))
        n_ips_per_org = max(2, int(3 * scale))
        n_persons_per_org = max(2, int(3 * scale))
        n_creds_per_org = max(1, int(2 * scale))
        n_certs = max(1, int(2 * scale))

        for org_idx in range(n_orgs):
            # ── Organization ──
            org_name = f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)} Holdings Ltd"
            org_props = {
                "object_type": ObjectType.ORGANIZATION,
                "name": org_name,
                "industry": random.choice(INDUSTRIES),
                "size": random.choice(["50-200", "200-500", "500-1000", "50-200"]),
                "country": "GB",
                "website": f"https://www.{random.choice(['techcore','datanest','cloudworks'])}.lab",
                "description": "Fabricated synthetic organization for deception deployment",
                "source": "labyrinth_synthetic",
            }
            org_id = self._create_mirror_node(ObjectType.ORGANIZATION, org_props)
            if org_id:
                self._mirror_nodes[org_id] = org_props
                stats["organizations"] += 1

            # ── Domains ──
            domain_ids: list[str] = []
            for d_idx in range(n_domains_per_org):
                prefix = random.choice(["techcore", "datanest", "cloudworks", "securenet", "bytestack"])
                suffix = random.choice([".com", ".net", ".co.uk", ".io", ".lab"])
                fake_domain = f"{prefix}{suffix}" if d_idx == 0 else f"{prefix}-{d_idx}{suffix}"
                domain_props = {
                    "object_type": ObjectType.DOMAIN,
                    "hostname": fake_domain,
                    "root_domain": fake_domain,
                    "registrar": random.choice(REGISTRARS),
                    "creation_date": date(2019 + random.randint(0, 4), random.randint(1, 12), random.randint(1, 28)).isoformat(),
                    "name_servers": ["ns1.lab.local", "ns2.lab.local"],
                    "source": "labyrinth_synthetic",
                }
                dom_id = self._create_mirror_node(ObjectType.DOMAIN, domain_props)
                if dom_id:
                    self._mirror_nodes[dom_id] = domain_props
                    domain_ids.append(dom_id)
                    stats["domains"] += 1
                    if org_id:
                        self._create_mirror_rel(org_id, dom_id, LinkType.OPERATES)
                        self._mirror_rels.append((org_id, dom_id, LinkType.OPERATES))

                # ── Subdomains ──
                for s_idx in range(n_subdomains_per_domain):
                    sub_prefix = random.choice(SUBDOMAIN_PREFIXES)
                    sub_props = {
                        "object_type": ObjectType.SUBDOMAIN,
                        "name": f"{sub_prefix}.{fake_domain}",
                        "parent_domain": fake_domain,
                        "is_wildcard": False,
                        "source": "labyrinth_synthetic",
                    }
                    sub_id = self._create_mirror_node(ObjectType.SUBDOMAIN, sub_props)
                    if sub_id:
                        self._mirror_nodes[sub_id] = sub_props
                        stats["subdomains"] += 1
                        if dom_id:
                            self._create_mirror_rel(dom_id, sub_id, LinkType.HAS_SUBDOMAIN)
                            self._mirror_rels.append((dom_id, sub_id, LinkType.HAS_SUBDOMAIN))

            # ── IP Addresses ──
            ip_ids: list[str] = []
            for i_idx in range(n_ips_per_org):
                pool = random.choice(FAKE_IP_POOL)
                octet = self._ip_counter
                self._ip_counter = (self._ip_counter + 1) if self._ip_counter < 250 else 10
                fake_ip = pool.format(octet)
                ip_props = {
                    "object_type": ObjectType.IP_ADDRESS,
                    "ip": fake_ip,
                    "asn": "AS64512",
                    "country": "GB",
                    "city": "London",
                    "isp": random.choice(["DigitalOcean", "AWS", "Linode", "Internal Lab Network"]),
                    "is_cloud": random.random() > 0.5,
                    "cloud_provider": random.choice(["AWS", "GCP", None]) if random.random() > 0.5 else None,
                    "source": "labyrinth_synthetic",
                }
                ip_id = self._create_mirror_node(ObjectType.IP_ADDRESS, ip_props)
                if ip_id:
                    self._mirror_nodes[ip_id] = ip_props
                    ip_ids.append(ip_id)
                    stats["ips"] += 1
                    # Link first IP to first domain
                    if domain_ids and i_idx < len(domain_ids):
                        self._create_mirror_rel(ip_id, domain_ids[i_idx], LinkType.RESOLVES_TO)
                        self._mirror_rels.append((ip_id, domain_ids[i_idx], LinkType.RESOLVES_TO))

            # ── Services on IPs with ports ──
            for ip_id in ip_ids:
                # Pick 2-4 services per IP
                n_services = random.randint(2, min(4, len(SERVICE_TEMPLATES)))
                chosen = random.sample(SERVICE_TEMPLATES, n_services)
                for template in chosen:
                    # Port
                    port_num = random.choice(template["ports"])
                    port_props = {
                        "object_type": ObjectType.PORT,
                        "port_number": port_num,
                        "protocol": "tcp",
                        "state": "open",
                        "banner": f"{template['name']} {template['version']}",
                        "source": "labyrinth_synthetic",
                    }
                    port_id = self._create_mirror_node(ObjectType.PORT, port_props)
                    if port_id:
                        self._mirror_nodes[port_id] = port_props
                        stats["ports"] += 1
                        self._create_mirror_rel(ip_id, port_id, LinkType.EXPOSES)
                        self._mirror_rels.append((ip_id, port_id, LinkType.EXPOSES))

                    # Service
                    svc_props = {
                        "object_type": ObjectType.SERVICE,
                        "name": template["name"],
                        "version": template["version"],
                        "cpe": template["cpe"],
                        "product": template["name"],
                        "os_type": "Linux",
                        "source": "labyrinth_synthetic",
                        "_template_key": template["name"],
                    }
                    svc_id = self._create_mirror_node(ObjectType.SERVICE, svc_props)
                    if svc_id:
                        self._mirror_nodes[svc_id] = svc_props
                        stats["services"] += 1
                        if port_id:
                            self._create_mirror_rel(port_id, svc_id, LinkType.RUNS)
                            self._mirror_rels.append((port_id, svc_id, LinkType.RUNS))

                        # CVEs for this service
                        cves = CVE_TEMPLATES.get(template["name"], [])
                        for cve_data in cves:
                            cve_props = {
                                "object_type": ObjectType.CVE,
                                "cve_id": cve_data["cve_id"],
                                "description": cve_data["description"],
                                "cvss_v3_score": cve_data["cvss_v3_score"],
                                "severity": cve_data["severity"].lower(),
                                "exploit_available": cve_data["exploit_available"],
                                "patch_available": False,
                                "source": "labyrinth_synthetic",
                            }
                            cve_id = self._create_mirror_node(ObjectType.CVE, cve_props)
                            if cve_id:
                                self._mirror_nodes[cve_id] = cve_props
                                stats["cves"] += 1
                                self._create_mirror_rel(svc_id, cve_id, LinkType.VULNERABLE_TO)
                                self._mirror_rels.append((svc_id, cve_id, LinkType.VULNERABLE_TO))

                                # ATT&CK technique
                                tech = random.choice(ATTACK_TECHNIQUE_POOL)
                                tech_props = {
                                    "object_type": ObjectType.ATTCK_TECHNIQUE,
                                    "technique_id": tech["technique_id"],
                                    "name": tech["name"],
                                    "tactic": tech["tactic"],
                                    "source": "labyrinth_synthetic",
                                }
                                tech_id = self._create_mirror_node(ObjectType.ATTCK_TECHNIQUE, tech_props)
                                if tech_id:
                                    self._mirror_nodes[tech_id] = tech_props
                                    stats["techniques"] += 1
                                    self._create_mirror_rel(cve_id, tech_id, LinkType.EXPLOITED_BY)
                                    self._mirror_rels.append((cve_id, tech_id, LinkType.EXPLOITED_BY))

                # ── Certificate on IP ──
                if random.random() > 0.3:
                    issuer = "Let's Encrypt R3" if random.random() > 0.3 else "DigiCert TLS RSA SHA256 2020 CA1"
                    now = datetime.now(timezone.utc)
                    cert_props = {
                        "object_type": ObjectType.CERTIFICATE,
                        "serial": uuid.uuid4().hex[:16],
                        "issuer": issuer,
                        "subject": f"CN=*.{random.choice(['techcore','datanest','cloudworks'])}.lab",
                        "not_before": (now - timedelta(days=random.randint(30, 180))).isoformat(),
                        "not_after": (now + timedelta(days=random.randint(30, 365))).isoformat(),
                        "fingerprint_sha256": uuid.uuid4().hex * 2,
                        "is_expired": False,
                        "is_self_signed": random.random() > 0.8,
                        "covers_domains": ["*.lab"],
                        "source": "labyrinth_synthetic",
                    }
                    cert_id = self._create_mirror_node(ObjectType.CERTIFICATE, cert_props)
                    if cert_id:
                        self._mirror_nodes[cert_id] = cert_props
                        stats["certificates"] += 1
                        self._create_mirror_rel(ip_id, cert_id, LinkType.HOSTS)
                        self._mirror_rels.append((ip_id, cert_id, LinkType.HOSTS))

            # ── Persons ──
            for p_idx in range(n_persons_per_org):
                first = random.choice(FIRST_NAMES)
                last = random.choice(LAST_NAMES)
                person_props = {
                    "object_type": ObjectType.PERSON,
                    "name": f"{first} {last}",
                    "email": f"{first.lower()}.{last.lower()}@lab.local",
                    "role": random.choice(ROLES),
                    "linkedin": f"linkedin.com/in/{first.lower()}-{last.lower()}",
                    "github": f"github.com/{first.lower()}{last.lower()}",
                    "source": "labyrinth_synthetic",
                }
                person_id = self._create_mirror_node(ObjectType.PERSON, person_props)
                if person_id:
                    self._mirror_nodes[person_id] = person_props
                    stats["persons"] += 1
                    if org_id:
                        self._create_mirror_rel(org_id, person_id, LinkType.BELONGS_TO)
                        self._mirror_rels.append((org_id, person_id, LinkType.BELONGS_TO))

                    # ── Credentials for this person ──
                    for c_idx in range(n_creds_per_org // max(n_persons_per_org, 1) + 1):
                        cred_props = {
                            "object_type": ObjectType.CREDENTIAL,
                            "email": f"{first.lower()}.{last.lower()}@lab.local",
                            "username": f"{first.lower()}.{last.lower()}",
                            "breach_name": random.choice(BREACH_SOURCES),
                            "breach_date": date(2023, random.randint(1, 12), random.randint(1, 28)).isoformat(),
                            "severity": random.choice(["low", "medium", "high"]),
                            "source": "labyrinth_synthetic",
                        }
                        cred_id = self._create_mirror_node(ObjectType.CREDENTIAL, cred_props)
                        if cred_id:
                            self._mirror_nodes[cred_id] = cred_props
                            stats["credentials"] += 1
                            if person_id:
                                self._create_mirror_rel(person_id, cred_id, LinkType.LEAKED_IN)
                                self._mirror_rels.append((person_id, cred_id, LinkType.LEAKED_IN))

        stats["mirror_nodes_total"] = len(self._mirror_nodes)
        stats["mirror_rels_total"] = len(self._mirror_rels)
        stats["scale"] = scale
        stats["mode"] = "synthetic"

        logger.info("EPHEMERAL LABYRINTH: SYNTHETIC generation complete — %d nodes, %d relationships",
                    stats["mirror_nodes_total"], stats["mirror_rels_total"])

        return stats

    def get_mirror_subgraph(self, depth: int = 3) -> dict[str, Any]:
        """Return the MirrorGraph subgraph for visualization/inspection."""
        node_records = cypher_read(
            "MATCH (n:MirrorNode) "
            "RETURN n.id AS id, labels(n) AS labels, properties(n) AS props"
        )
        rel_records = cypher_read(
            "MATCH (a:MirrorNode)-[r]->(b:MirrorNode) "
            "RETURN a.id AS source_id, b.id AS target_id, type(r) AS rel_type, properties(r) AS props"
        )
        return {
            "nodes": node_records,
            "edges": rel_records,
            "total_nodes": len(node_records),
            "total_edges": len(rel_records),
        }

    def clear_mirror(self) -> int:
        """Delete all MirrorGraph nodes and relationships. Returns count deleted."""
        return self._clear_mirror()

    def get_mapping(self) -> dict[str, str]:
        """Return the true_id → mirror_id mapping."""
        return dict(self._generated)

    # ── NODE FABRICATION ──────────────────────────────────────────────

    def _fabricate_node(self, obj_type: str, real_props: dict, scale: float) -> Optional[dict]:
        """Generate a fabricated version of a real node."""
        fabricators = {
            ObjectType.ORGANIZATION: self._fabricate_organization,
            ObjectType.DOMAIN: self._fabricate_domain,
            ObjectType.SUBDOMAIN: self._fabricate_subdomain,
            ObjectType.IP_ADDRESS: self._fabricate_ip,
            ObjectType.PORT: self._fabricate_port,
            ObjectType.SERVICE: self._fabricate_service,
            ObjectType.CVE: self._fabricate_cve,
            ObjectType.PERSON: self._fabricate_person,
            ObjectType.CREDENTIAL: self._fabricate_credential,
            ObjectType.CERTIFICATE: self._fabricate_certificate,
        }

        fabricator = fabricators.get(obj_type)
        if not fabricator:
            return None

        return fabricator(real_props)

    def _fabricate_organization(self, real: dict) -> dict:
        """Clone org structure with a fabricated name."""
        return {
            "object_type": ObjectType.ORGANIZATION,
            "name": f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)} Holdings Ltd",
            "industry": random.choice(INDUSTRIES),
            "size": real.get("size", "50-200"),
            "country": real.get("country", "GB"),
            "description": f"Fabricated mirror of {real.get('name', 'unknown org')}",
            "source": "labyrinth_mirror",
        }

    def _fabricate_domain(self, real: dict) -> dict:
        """Generate a fabricated but resolvable-looking domain."""
        prefixes = ["tech", "cloud", "data", "secure", "net", "digital", "cyber", "byte"]
        suffixes = ["solutions", "systems", "group", "labs", "works", "hub", "stack", "forge"]
        fake_domain = f"{random.choice(prefixes)}{random.choice(suffixes)}.lab"

        return {
            "object_type": ObjectType.DOMAIN,
            "hostname": fake_domain,
            "root_domain": fake_domain,
            "registrar": random.choice(REGISTRARS),
            "creation_date": date(2019, random.randint(1, 12), random.randint(1, 28)).isoformat(),
            "name_servers": ["ns1.lab.local", "ns2.lab.local"],
            "source": "labyrinth_mirror",
        }

    def _fabricate_subdomain(self, real: dict) -> dict:
        """Generate a fabricated subdomain."""
        prefix = random.choice(SUBDOMAIN_PREFIXES)
        return {
            "object_type": ObjectType.SUBDOMAIN,
            "name": f"{prefix}.lab",
            "parent_domain": "lab",
            "is_wildcard": False,
            "source": "labyrinth_mirror",
        }

    def _fabricate_ip(self, real: dict) -> dict:
        """Generate a documentation-range IP that looks real."""
        pool = random.choice(FAKE_IP_POOL)
        octet = self._ip_counter
        self._ip_counter = (self._ip_counter + 1) if self._ip_counter < 250 else 10
        fake_ip = pool.format(octet)

        return {
            "object_type": ObjectType.IP_ADDRESS,
            "ip": fake_ip,
            "asn": real.get("asn", "AS64512"),
            "country": real.get("country", "GB"),
            "isp": real.get("isp", "Internal Lab Network"),
            "is_cloud": False,
            "source": "labyrinth_mirror",
        }

    def _fabricate_port(self, real: dict) -> dict:
        """Clone port — ports are generic, keep the number."""
        return {
            "object_type": ObjectType.PORT,
            "port_number": real.get("port_number", random.choice([22, 80, 443, 3306, 6379, 8080])),
            "protocol": real.get("protocol", "tcp"),
            "state": "open",
            "banner": real.get("banner"),
            "source": "labyrinth_mirror",
        }

    def _fabricate_service(self, real: dict) -> dict:
        """Fabricate a plausible service with matching CVEs.

        Port-aware: if the real service was running on a known port,
        pick a template that's valid for that port. This prevents the
        consistency validator from flagging port-service mismatches.
        """
        port_num = real.get("_port_number")

        if port_num and port_num in PORT_SERVICE_MAP:
            valid_names = PORT_SERVICE_MAP[port_num]
            valid_templates = [t for t in SERVICE_TEMPLATES if t["name"] in valid_names]
            if valid_templates:
                template = random.choice(valid_templates)
            else:
                template = {
                    "name": real.get("name", "unknown"),
                    "version": real.get("version", "1.0"),
                    "cpe": real.get("cpe", ""),
                    "ports": [port_num],
                }
        else:
            template = random.choice(SERVICE_TEMPLATES)

        return {
            "object_type": ObjectType.SERVICE,
            "name": template["name"],
            "version": template["version"],
            "cpe": template["cpe"],
            "product": template["name"],
            "os_type": "Linux",
            "source": "labyrinth_mirror",
            "_template_key": template["name"],
        }

    def _fabricate_cve(self, real: dict) -> dict:
        """Fabricate a CVE that matches the service it's linked to.

        Service-aware: if we know which service this CVE belongs to
        (via _service_name injected by generate_mirror), pick a CVE
        from CVE_TEMPLATES that actually affects that service.
        """
        service_name = real.get("_service_name", "")

        if service_name and service_name in CVE_TEMPLATES:
            cve_data = random.choice(CVE_TEMPLATES[service_name])
            return {
                "object_type": ObjectType.CVE,
                "cve_id": cve_data["cve_id"],
                "description": cve_data["description"],
                "cvss_v3_score": cve_data["cvss_v3_score"],
                "severity": cve_data["severity"].lower(),
                "exploit_available": cve_data["exploit_available"],
                "patch_available": False,
                "source": "labyrinth_mirror",
            }

        # Fallback: clone the real CVE
        return {
            "object_type": ObjectType.CVE,
            "cve_id": real.get("cve_id", "CVE-UNKNOWN"),
            "description": real.get("description", ""),
            "cvss_v3_score": real.get("cvss_v3_score", 5.0),
            "severity": real.get("severity", "medium"),
            "published_date": real.get("published_date"),
            "exploit_available": real.get("exploit_available", True),
            "patch_available": real.get("patch_available", False),
            "source": "labyrinth_mirror",
        }

    def _fabricate_person(self, real: dict) -> dict:
        """Generate a fabricated person."""
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        name = f"{first} {last}"
        return {
            "object_type": ObjectType.PERSON,
            "name": name,
            "email": f"{first.lower()}.{last.lower()}@lab.local",
            "role": random.choice(ROLES),
            "source": "labyrinth_mirror",
        }

    def _fabricate_credential(self, real: dict) -> dict:
        """Generate a fabricated leaked credential."""
        first = random.choice(FIRST_NAMES).lower()
        last = random.choice(LAST_NAMES).lower()
        return {
            "object_type": ObjectType.CREDENTIAL,
            "email": f"{first}.{last}@lab.local",
            "username": f"{first}.{last}",
            "breach_name": random.choice(BREACH_SOURCES),
            "breach_date": date(2023, random.randint(1, 12), random.randint(1, 28)).isoformat(),
            "source": "labyrinth_mirror",
        }

    def _fabricate_certificate(self, real: dict) -> dict:
        """Generate a fabricated TLS certificate."""
        issuer = "Let's Encrypt R3" if random.random() > 0.3 else "DigiCert TLS RSA SHA256 2020 CA1"
        now = datetime.now(timezone.utc)
        return {
            "object_type": ObjectType.CERTIFICATE,
            "serial": uuid.uuid4().hex[:16],
            "issuer": issuer,
            "subject": "CN=*.lab.local",
            "not_before": (now - timedelta(days=random.randint(30, 180))).isoformat(),
            "not_after": (now + timedelta(days=random.randint(30, 365))).isoformat(),
            "fingerprint_sha256": uuid.uuid4().hex * 2,  # 64 char hex
            "source": "labyrinth_mirror",
        }

    # ── EXTRA DECEPTION NODES ─────────────────────────────────────────

    def _generate_extras(self, scale: float) -> dict[str, int]:
        """Generate additional fake-only nodes that don't exist in TrueGraph.

        These add depth to the maze — extra services, credentials, and
        subdomains that make the MirrorGraph look like a richer target.
        """
        stats: dict[str, int] = {}
        n_extra_services = int(5 * scale)
        n_extra_creds = int(3 * scale)
        n_extra_subdomains = int(8 * scale)

        # Extra services with matching CVEs
        for i in range(n_extra_services):
            template = random.choice(SERVICE_TEMPLATES)
            service_key = template["name"]
            props = {
                "object_type": ObjectType.SERVICE,
                "name": template["name"],
                "version": template["version"],
                "cpe": template["cpe"],
                "product": template["name"],
                "os_type": "Linux",
                "source": "labyrinth_mirror",
                "_template_key": service_key,
            }
            mirror_id = self._create_mirror_node(ObjectType.SERVICE, props)
            if mirror_id:
                self._mirror_nodes[mirror_id] = props
                stats["services"] = stats.get("services", 0) + 1

                # Attach matching CVEs
                cves = CVE_TEMPLATES.get(service_key, [])
                for cve_data in cves:
                    cve_props = {
                        "object_type": ObjectType.CVE,
                        "cve_id": cve_data["cve_id"],
                        "description": cve_data["description"],
                        "cvss_v3_score": cve_data["cvss_v3_score"],
                        "severity": cve_data["severity"],
                        "exploit_available": cve_data["exploit_available"],
                        "source": "labyrinth_mirror",
                    }
                    cve_id = self._create_mirror_node(ObjectType.CVE, cve_props)
                    if cve_id:
                        self._mirror_nodes[cve_id] = cve_props
                        self._create_mirror_rel(mirror_id, cve_id, LinkType.VULNERABLE_TO)
                        self._mirror_rels.append((mirror_id, cve_id, LinkType.VULNERABLE_TO))
                        stats["cves"] = stats.get("cves", 0) + 1

                        # Attach ATT&CK technique
                        tech = random.choice(ATTACK_TECHNIQUE_POOL)
                        tech_props = {
                            "object_type": ObjectType.ATTCK_TECHNIQUE,
                            "technique_id": tech["technique_id"],
                            "name": tech["name"],
                            "tactic": tech["tactic"],
                            "source": "labyrinth_mirror",
                        }
                        tech_id = self._create_mirror_node(ObjectType.ATTCK_TECHNIQUE, tech_props)
                        if tech_id:
                            self._mirror_nodes[tech_id] = tech_props
                            self._create_mirror_rel(cve_id, tech_id, LinkType.EXPLOITED_BY)
                            self._mirror_rels.append((cve_id, tech_id, LinkType.EXPLOITED_BY))
                            stats["techniques"] = stats.get("techniques", 0) + 1

        # Extra credentials
        for i in range(n_extra_creds):
            first = random.choice(FIRST_NAMES).lower()
            last = random.choice(LAST_NAMES).lower()
            props = {
                "object_type": ObjectType.CREDENTIAL,
                "email": f"{first}.{last}@lab.local",
                "username": f"{first}.{last}",
                "breach_name": random.choice(BREACH_SOURCES),
                "breach_date": date(2023, random.randint(1, 12), random.randint(1, 28)).isoformat(),
                "source": "labyrinth_mirror",
            }
            mid = self._create_mirror_node(ObjectType.CREDENTIAL, props)
            if mid:
                self._mirror_nodes[mid] = props
                stats["credentials"] = stats.get("credentials", 0) + 1

        # Extra subdomains
        for i in range(n_extra_subdomains):
            prefix = random.choice(SUBDOMAIN_PREFIXES)
            props = {
                "object_type": ObjectType.SUBDOMAIN,
                "name": f"{prefix}.lab",
                "parent_domain": "lab",
                "is_wildcard": False,
                "source": "labyrinth_mirror",
            }
            mid = self._create_mirror_node(ObjectType.SUBDOMAIN, props)
            if mid:
                self._mirror_nodes[mid] = props
                stats["subdomains"] = stats.get("subdomains", 0) + 1

        return stats

    # ── NEO4J OPERATIONS (using PITBULL's cypher_write/cypher_read) ─────

    def _create_mirror_node(self, obj_type: str, props: dict) -> Optional[str]:
        """Create a node in Neo4j with the MirrorNode label."""
        if "id" not in props or not props["id"]:
            props["id"] = str(uuid.uuid4())
        props["object_type"] = obj_type

        props["__mirror__"] = True
        props["first_seen"] = datetime.now(timezone.utc).isoformat()
        props["last_seen"] = datetime.now(timezone.utc).isoformat()
        props["source"] = "labyrinth_mirror"

        # Remove internal keys before storing
        clean_props = {k: v for k, v in props.items() if not k.startswith("_") and v is not None}

        # Determine merge key
        merge_key = _MERGE_KEYS.get(obj_type)
        if merge_key and merge_key in clean_props:
            cypher = (
                f"MERGE (n:{obj_type}:MirrorNode {{{merge_key}: $props.{merge_key}, __mirror__: true}}) "
                f"SET n += $props "
                f"RETURN n.id AS id"
            )
        else:
            cypher = (
                f"CREATE (n:{obj_type}:MirrorNode) "
                f"SET n = $props "
                f"RETURN n.id AS id"
            )

        records = cypher_write(cypher, params={"props": clean_props})
        if records:
            return records[0]["id"]
        return None

    def _create_mirror_rel(self, source_id: str, target_id: str, link_type: str) -> bool:
        """Create a relationship between two mirror nodes."""
        cypher_write(
            f"""
            MATCH (a:MirrorNode {{id: $sid}})
            MATCH (b:MirrorNode {{id: $tid}})
            MERGE (a)-[r:{link_type}]->(b)
            SET r.__mirror__ = true,
                r.first_seen = datetime(),
                r.last_seen = datetime(),
                r.source = 'labyrinth_mirror'
            RETURN type(r) AS type
            """,
            params={"sid": source_id, "tid": target_id},
        )
        return True

    def _clear_mirror(self) -> int:
        """Delete all MirrorGraph nodes and relationships."""
        cypher_write("MATCH (a:MirrorNode)-[r]->(b:MirrorNode) DELETE r")
        records = cypher_write("MATCH (n:MirrorNode) DELETE n RETURN count(n) AS count")
        count = records[0]["count"] if records else 0

        self._generated.clear()
        self._mirror_nodes.clear()
        self._mirror_rels.clear()
        self._ip_counter = 10

        if count:
            logger.info("EPHEMERAL LABYRINTH: Cleared %d existing mirror nodes", count)
        return count

    # ── HELPERS ───────────────────────────────────────────────────────

    @staticmethod
    def _get_type(node: dict) -> str:
        return node.get("object_type") or node.get("props", {}).get("object_type", "")

    @staticmethod
    def _get_props(node: dict) -> dict:
        return node.get("props", node)


# ── Singleton ────────────────────────────────────────────────────────────

_engine: Optional[MirrorGraphEngine] = None


def get_mirror_engine() -> MirrorGraphEngine:
    global _engine
    if _engine is None:
        _engine = MirrorGraphEngine()
    return _engine