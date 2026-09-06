"""Ontology Consistency Validator — ensures the MirrorGraph has no contradictions.

This is the key innovation. Previous deception systems failed because their fakes
were inconsistent — a fake service would claim to be MySQL but the port said 22,
or a fake CVE wouldn't match the service version. An attacker could detect these
mismatches and dismiss the entire deception layer.

The validator checks:
1. Domain → resolves → IP (does the IP exist in the graph?)
2. IP → exposes → Port (is the port number plausible for the service?)
3. Port → runs → Service (does the service match the port?)
4. Service → vulnerable_to → CVE (does the CVE actually affect this service?)
5. CVE → exploited_by → ATTCKTechnique (is the technique real and relevant?)
6. Person → operates → Organization (does the org exist?)
7. Person → covers → Credential (does the email domain match?)
8. Certificate → covers → Domain (does the domain exist in the graph?)
9. No orphan nodes (every node should have at least one relationship)
10. No duplicate natural keys (same hostname, IP, CVE ID appearing twice)

If any check fails, the validator returns the specific contradiction so it can
be fixed before the attacker sees it.

Academic basis:
- Palantir ontology: relationships must be internally consistent
- Polad et al. 2019: "If the fake information is naive or poorly chosen, the
  attacker may immediately become suspicious"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.database import cypher_read

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
#  OBJECT TYPE AND LINK TYPE CONSTANTS (inlined — no ontology engine in PITBULL)
# ═══════════════════════════════════════════════════════════════════════

# Object types — match PITBULL's Neo4j node labels
class ObjectType:
    ORGANIZATION = "Organization"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    IP_ADDRESS = "IPAddress"
    PORT = "Port"
    SERVICE = "Service"
    CVE = "CVE"
    ATTCK_TECHNIQUE = "ATTCKTechnique"
    PERSON = "Person"
    CREDENTIAL = "Credential"
    CERTIFICATE = "Certificate"
    ONION_SERVICE = "OnionService"
    MEMORY = "Memory"
    NODE = "Node"
    OPINION = "Opinion"
    MIRROR_NODE = "MirrorNode"
    MIRROR_SERVICE = "MirrorService"
    FAKE_CREDENTIAL = "FakeCredential"


# Link types — match PITBULL's Neo4j relationship types
class LinkType:
    OPERATES = "OPERATES"
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    EXPOSES = "EXPOSES"
    RUNS = "RUNS"
    VULNERABLE_TO = "VULNERABLE_TO"
    EXPLOITED_BY = "EXPLOITED_BY"
    BELONGS_TO = "BELONGS_TO"
    LEAKED_IN = "LEAKED_IN"
    HOSTS = "HOSTS"
    COVERS = "COVERS"


# Severity levels (inlined)
class SeverityLevel:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ═══════════════════════════════════════════════════════════════════════
#  VALIDATION RESULT
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class Violation:
    """A single consistency violation in the MirrorGraph."""
    check: str           # name of the check that failed
    severity: str        # "critical", "high", "medium", "low"
    node_id: str         # the offending node
    node_type: str       # object type
    details: str         # human-readable explanation
    fix_hint: str = ""   # suggested fix


@dataclass
class ValidationResult:
    """Result of a full MirrorGraph consistency validation."""
    total_nodes: int = 0
    total_edges: int = 0
    violations: list[Violation] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not any(v.severity == "critical" for v in self.violations)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "high")

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if v.severity in ("medium", "low"))

    def summary(self) -> str:
        return (f"Validation: {'PASS' if self.is_valid else 'FAIL'} | "
                f"{self.total_nodes} nodes, {self.total_edges} edges | "
                f"{self.critical_count} critical, {self.high_count} high, {self.warning_count} warnings")


# ═══════════════════════════════════════════════════════════════════════
#  PORT-SERVICE CONSISTENCY TABLE
# ═══════════════════════════════════════════════════════════════════════

# Which ports are plausible for which services
PORT_SERVICE_MAP = {
    22: {"OpenSSH", "SSH"},
    80: {"nginx", "Apache httpd", "Node.js Express", "WordPress", "GitLab CE", "phpMyAdmin"},
    443: {"nginx", "Apache httpd", "Node.js Express", "WordPress", "GitLab CE", "phpMyAdmin"},
    3306: {"MySQL"},
    5432: {"PostgreSQL"},
    6379: {"Redis"},
    8080: {"Apache Tomcat", "Node.js Express", "Jenkins", "Grafana"},
    8443: {"Apache Tomcat"},
    3000: {"Node.js Express", "Grafana"},
    5000: {"Docker Registry"},
    9200: {"Elasticsearch"},
    9300: {"Elasticsearch"},
    5601: {"Kibana"},
    27017: {"MongoDB"},
    5672: {"RabbitMQ"},
    15672: {"RabbitMQ"},
    50000: {"Jenkins"},
}

# Services and their known CVEs (must match CVE_TEMPLATES in mirror_graph.py)
SERVICE_CVE_MAP = {
    "nginx": {"CVE-2024-7347", "CVE-2023-44487"},
    "Apache httpd": {"CVE-2023-45802", "CVE-2023-31122"},
    "OpenSSH": {"CVE-2023-38408", "CVE-2023-48795"},
    "MySQL": {"CVE-2023-22084", "CVE-2023-22007"},
    "PostgreSQL": {"CVE-2023-39417", "CVE-2023-5868"},
    "Redis": {"CVE-2023-41053", "CVE-2023-28856"},
    "Apache Tomcat": {"CVE-2023-46589", "CVE-2023-42794"},
    "Jenkins": {"CVE-2023-41931", "CVE-2024-23897"},
    "GitLab CE": {"CVE-2023-7028", "CVE-2023-4839"},
    "WordPress": {"CVE-2023-2745", "CVE-2023-3460"},
    "MongoDB": {"CVE-2023-1409"},
    "Elasticsearch": {"CVE-2023-31413"},
    "Grafana": {"CVE-2023-6152"},
    "Kibana": {"CVE-2023-31415"},
    "phpMyAdmin": {"CVE-2023-25054"},
    "RabbitMQ": {"CVE-2023-46120"},
    "Node.js Express": {"CVE-2023-26136"},
    "Docker Registry": {"CVE-2023-2253"},
}

# Valid link types for relationship validation
VALID_LINK_TYPES = {
    LinkType.OPERATES, LinkType.HAS_SUBDOMAIN, LinkType.RESOLVES_TO,
    LinkType.EXPOSES, LinkType.RUNS, LinkType.VULNERABLE_TO,
    LinkType.EXPLOITED_BY, LinkType.BELONGS_TO, LinkType.LEAKED_IN,
    LinkType.HOSTS, LinkType.COVERS,
}


class ConsistencyValidator:
    """Validates the MirrorGraph for ontological consistency.

    The goal: an attacker cross-referencing every property, every relationship,
    every derived fact should find ZERO contradictions. If they do find one,
    the entire deception is blown.

    This validator runs after MirrorGraph generation and before any attacker
    is allowed to see the MirrorGraph.
    """

    def validate(self) -> ValidationResult:
        """Run all consistency checks against the MirrorGraph."""
        result = ValidationResult()

        # Fetch the full MirrorGraph using PITBULL's cypher_read
        nodes = cypher_read(
            "MATCH (n:MirrorNode) RETURN n.id AS id, labels(n) AS labels, properties(n) AS props"
        )
        rels = cypher_read(
            "MATCH (a:MirrorNode)-[r]->(b:MirrorNode) "
            "RETURN a.id AS source_id, b.id AS target_id, type(r) AS rel_type, properties(r) AS props"
        )

        result.total_nodes = len(nodes)
        result.total_edges = len(rels)

        if not nodes:
            result.violations.append(Violation(
                check="graph_empty",
                severity="critical",
                node_id="",
                node_type="",
                details="MirrorGraph is empty — nothing to validate",
            ))
            return result

        logger.info("EPHEMERAL LABYRINTH: Validating MirrorGraph — %d nodes, %d edges", len(nodes), len(rels))

        # Build lookup structures
        nodes_by_id: dict[str, dict] = {}
        nodes_by_type: dict[str, list[dict]] = {}
        for n in nodes:
            props = n.get("props", {})
            nid = n.get("id") or props.get("id", "")
            nodes_by_id[nid] = {**props, "id": nid, "_labels": n.get("labels", [])}
            ot = props.get("object_type", "")
            nodes_by_type.setdefault(ot, []).append(nodes_by_id[nid])

        # Build edge adjacency
        edges_by_source: dict[str, list[dict]] = {}
        edges_by_target: dict[str, list[dict]] = {}
        for e in rels:
            src = e.get("source_id", "")
            tgt = e.get("target_id", "")
            edges_by_source.setdefault(src, []).append(e)
            edges_by_target.setdefault(tgt, []).append(e)

        # ── Run all checks ───────────────────────────────────────────

        # 1. Port-Service consistency
        result.checks_run.append("port_service_match")
        self._check_port_service(nodes_by_type, edges_by_source, result)

        # 2. Service-CVE consistency
        result.checks_run.append("service_cve_match")
        self._check_service_cve(nodes_by_type, edges_by_source, result)

        # 3. CVE-Technique consistency
        result.checks_run.append("cve_technique_valid")
        self._check_cve_technique(nodes_by_type, edges_by_source, result)

        # 4. Domain-IP resolution consistency
        result.checks_run.append("domain_ip_resolution")
        self._check_domain_ip(nodes_by_type, edges_by_source, result)

        # 5. Person-Org consistency
        result.checks_run.append("person_org")
        self._check_person_org(nodes_by_type, edges_by_source, result)

        # 6. Credential-Person consistency
        result.checks_run.append("credential_person")
        self._check_credential_person(nodes_by_type, edges_by_source, result)

        # 7. Certificate-Domain consistency
        result.checks_run.append("certificate_domain")
        self._check_cert_domain(nodes_by_type, edges_by_source, result)

        # 8. Orphan check
        result.checks_run.append("orphan_nodes")
        self._check_orphans(nodes_by_id, edges_by_source, edges_by_target, result)

        # 9. Duplicate natural keys
        result.checks_run.append("duplicate_keys")
        self._check_duplicates(nodes_by_type, result)

        # 10. Relationship type validity
        result.checks_run.append("relationship_validity")
        self._check_relationship_types(rels, nodes_by_id, result)

        logger.info("EPHEMERAL LABYRINTH: Validation complete — %s", result.summary())

        return result

    # ── INDIVIDUAL CHECKS ─────────────────────────────────────────────

    def _check_port_service(
        self,
        nodes_by_type: dict[str, list[dict]],
        edges_by_source: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check that ports run services that are plausible for that port number."""
        ports = nodes_by_type.get(ObjectType.PORT, [])
        services_by_id = {s["id"]: s for s in nodes_by_type.get(ObjectType.SERVICE, [])}

        for port in ports:
            port_num = port.get("port_number")
            if port_num is None:
                continue

            # Find services connected to this port via RUNS edge
            outgoing = edges_by_source.get(port["id"], [])
            for edge in outgoing:
                if edge.get("rel_type") != LinkType.RUNS:
                    continue
                svc_id = edge.get("target_id", "")
                service = services_by_id.get(svc_id)
                if not service:
                    continue

                svc_name = service.get("name", "")
                valid_services = PORT_SERVICE_MAP.get(int(port_num), set())

                if valid_services and svc_name not in valid_services:
                    result.violations.append(Violation(
                        check="port_service_match",
                        severity="high",
                        node_id=port["id"],
                        node_type=ObjectType.PORT,
                        details=f"Port {port_num} runs '{svc_name}' — expected one of {valid_services}",
                        fix_hint=f"Change port to match service, or service to match port {port_num}",
                    ))

    def _check_service_cve(
        self,
        nodes_by_type: dict[str, list[dict]],
        edges_by_source: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check that CVEs linked to services actually affect those services."""
        services = nodes_by_type.get(ObjectType.SERVICE, [])
        cves_by_id = {c["id"]: c for c in nodes_by_type.get(ObjectType.CVE, [])}

        for service in services:
            svc_name = service.get("name", "")
            valid_cves = SERVICE_CVE_MAP.get(svc_name, set())

            outgoing = edges_by_source.get(service["id"], [])
            for edge in outgoing:
                if edge.get("rel_type") != LinkType.VULNERABLE_TO:
                    continue
                cve_id = edge.get("target_id", "")
                cve = cves_by_id.get(cve_id)
                if not cve:
                    continue

                cve_code = cve.get("cve_id", "")
                if valid_cves and cve_code not in valid_cves:
                    result.violations.append(Violation(
                        check="service_cve_match",
                        severity="critical",
                        node_id=service["id"],
                        node_type=ObjectType.SERVICE,
                        details=f"Service '{svc_name}' linked to {cve_code} which doesn't affect this service",
                        fix_hint=f"Use one of {valid_cves} for {svc_name}",
                    ))

    def _check_cve_technique(
        self,
        nodes_by_type: dict[str, list[dict]],
        edges_by_source: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check that CVE → ATT&CK technique links are valid."""
        cves = nodes_by_type.get(ObjectType.CVE, [])
        techniques_by_id = {t["id"]: t for t in nodes_by_type.get(ObjectType.ATTCK_TECHNIQUE, [])}

        for cve in cves:
            outgoing = edges_by_source.get(cve["id"], [])
            for edge in outgoing:
                if edge.get("rel_type") != LinkType.EXPLOITED_BY:
                    continue
                tech_id = edge.get("target_id", "")
                tech = techniques_by_id.get(tech_id)
                if not tech:
                    result.violations.append(Violation(
                        check="cve_technique_valid",
                        severity="medium",
                        node_id=cve["id"],
                        node_type=ObjectType.CVE,
                        details=f"CVE {cve.get('cve_id', '')} links to non-existent technique {tech_id}",
                        fix_hint="Create the technique node or remove the link",
                    ))

    def _check_domain_ip(
        self,
        nodes_by_type: dict[str, list[dict]],
        edges_by_source: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check that domain/subdomain → IP resolution targets exist."""
        domains = nodes_by_type.get(ObjectType.DOMAIN, []) + nodes_by_type.get(ObjectType.SUBDOMAIN, [])
        ips_by_id = {ip["id"]: ip for ip in nodes_by_type.get(ObjectType.IP_ADDRESS, [])}

        for domain in domains:
            outgoing = edges_by_source.get(domain["id"], [])
            for edge in outgoing:
                if edge.get("rel_type") != LinkType.RESOLVES_TO:
                    continue
                ip_id = edge.get("target_id", "")
                if ip_id not in ips_by_id:
                    result.violations.append(Violation(
                        check="domain_ip_resolution",
                        severity="high",
                        node_id=domain["id"],
                        node_type=domain.get("object_type", ""),
                        details=f"Domain {domain.get('hostname', domain.get('name', ''))} resolves to non-existent IP node {ip_id}",
                        fix_hint="Create the IP node or remove the resolution link",
                    ))

    def _check_person_org(
        self,
        nodes_by_type: dict[str, list[dict]],
        edges_by_source: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check that persons link to existing organizations."""
        persons = nodes_by_type.get(ObjectType.PERSON, [])
        orgs_by_id = {o["id"]: o for o in nodes_by_type.get(ObjectType.ORGANIZATION, [])}

        for person in persons:
            outgoing = edges_by_source.get(person["id"], [])
            for edge in outgoing:
                if edge.get("rel_type") != LinkType.OPERATES and edge.get("rel_type") != LinkType.BELONGS_TO:
                    continue
                org_id = edge.get("target_id", "")
                if org_id not in orgs_by_id:
                    result.violations.append(Violation(
                        check="person_org",
                        severity="medium",
                        node_id=person["id"],
                        node_type=ObjectType.PERSON,
                        details=f"Person {person.get('name', '')} links to non-existent org {org_id}",
                        fix_hint="Create the org node or remove the link",
                    ))

    def _check_credential_person(
        self,
        nodes_by_type: dict[str, list[dict]],
        edges_by_source: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check that credentials reference existing persons (email domain match)."""
        creds = nodes_by_type.get(ObjectType.CREDENTIAL, [])
        persons = nodes_by_type.get(ObjectType.PERSON, [])
        person_emails = {p.get("email", "").lower() for p in persons if p.get("email")}

        for cred in creds:
            cred_email = cred.get("email", "").lower()
            if cred_email and cred_email not in person_emails:
                # Check if the email domain at least matches
                cred_domain = cred_email.split("@")[-1] if "@" in cred_email else ""
                person_domains = {e.split("@")[-1] for e in person_emails if "@" in e}
                if cred_domain and cred_domain not in person_domains:
                    result.violations.append(Violation(
                        check="credential_person",
                        severity="low",
                        node_id=cred["id"],
                        node_type=ObjectType.CREDENTIAL,
                        details=f"Credential email {cred_email} doesn't match any person's email domain",
                        fix_hint="Create a person with matching email domain or change credential email",
                    ))

    def _check_cert_domain(
        self,
        nodes_by_type: dict[str, list[dict]],
        edges_by_source: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check that certificates cover existing domains."""
        certs = nodes_by_type.get(ObjectType.CERTIFICATE, [])
        domains_by_id = {d["id"]: d for d in nodes_by_type.get(ObjectType.DOMAIN, [])}

        for cert in certs:
            outgoing = edges_by_source.get(cert["id"], [])
            for edge in outgoing:
                if edge.get("rel_type") != LinkType.COVERS:
                    continue
                domain_id = edge.get("target_id", "")
                if domain_id not in domains_by_id:
                    result.violations.append(Violation(
                        check="certificate_domain",
                        severity="low",
                        node_id=cert["id"],
                        node_type=ObjectType.CERTIFICATE,
                        details=f"Certificate covers non-existent domain {domain_id}",
                        fix_hint="Create the domain or remove the certificate link",
                    ))

    def _check_orphans(
        self,
        nodes_by_id: dict[str, dict],
        edges_by_source: dict[str, list[dict]],
        edges_by_target: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check for orphan nodes (no relationships)."""
        for nid, node in nodes_by_id.items():
            has_outgoing = bool(edges_by_source.get(nid))
            has_incoming = bool(edges_by_target.get(nid))
            if not has_outgoing and not has_incoming:
                # ATTCKTechnique nodes might be referenced by real CVEs, skip
                if node.get("object_type") == ObjectType.ATTCK_TECHNIQUE:
                    continue
                result.violations.append(Violation(
                    check="orphan_nodes",
                    severity="medium",
                    node_id=nid,
                    node_type=node.get("object_type", ""),
                    details=f"Orphan node with no relationships: {node.get('hostname', node.get('ip', node.get('name', node.get('cve_id', nid))))}",
                    fix_hint="Add at least one relationship to connect this node",
                ))

    def _check_duplicates(
        self,
        nodes_by_type: dict[str, list[dict]],
        result: ValidationResult,
    ) -> None:
        """Check for duplicate natural keys within the same object type."""
        key_fields = {
            ObjectType.DOMAIN: "hostname",
            ObjectType.SUBDOMAIN: "name",
            ObjectType.IP_ADDRESS: "ip",
            ObjectType.CVE: "cve_id",
            ObjectType.ATTCK_TECHNIQUE: "technique_id",
            ObjectType.PERSON: "email",
            ObjectType.ORGANIZATION: "name",
        }

        for obj_type, key_field in key_fields.items():
            nodes = nodes_by_type.get(obj_type, [])
            seen: dict[str, list[str]] = {}
            for node in nodes:
                key_val = node.get(key_field, "")
                if key_val:
                    seen.setdefault(key_val, []).append(node["id"])
            for key_val, ids in seen.items():
                if len(ids) > 1:
                    result.violations.append(Violation(
                        check="duplicate_keys",
                        severity="high",
                        node_id=ids[0],
                        node_type=obj_type,
                        details=f"Duplicate {key_field} '{key_val}' on nodes: {', '.join(ids)}",
                        fix_hint="Merge duplicate nodes or change one to be unique",
                    ))

    def _check_relationship_types(
        self,
        edges: list[dict],
        nodes_by_id: dict[str, dict],
        result: ValidationResult,
    ) -> None:
        """Check that relationship types are valid ontology link types."""
        for edge in edges:
            rel_type = edge.get("rel_type", "")
            if rel_type and rel_type not in VALID_LINK_TYPES:
                result.violations.append(Violation(
                    check="relationship_validity",
                    severity="medium",
                    node_id=edge.get("source_id", ""),
                    node_type="",
                    details=f"Unknown relationship type '{rel_type}'",
                    fix_hint=f"Use one of {VALID_LINK_TYPES}",
                ))


# ── Singleton ────────────────────────────────────────────────────────────

_validator: Optional[ConsistencyValidator] = None


def get_consistency_validator() -> ConsistencyValidator:
    global _validator
    if _validator is None:
        _validator = ConsistencyValidator()
    return _validator