"""PITBULL Spreading Activation — related memory activation on new findings.

When a new node is added to the graph, related nodes are activated.
This creates serendipitous discoveries — "I found this IP, and it reminds
me of something I saw 3 weeks ago..."

Academic basis:
- SYNAPSE (ACL 2026): spreading activation in memory graph
- Memory Beyond Recall (arXiv:2606.09483): dual-process cognitive memory
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)

# Activation decay — each hop reduces activation by this factor
DECAY = 0.5
# Minimum activation to be considered "activated"
ACTIVATION_THRESHOLD = 0.15
# Maximum hops to spread
MAX_HOPS = 3


class SpreadingActivation:
    """Spreading activation over the Neo4j memory graph."""

    def activate_from_node(self, node_id: int, node_type: str, label: str) -> list[dict[str, Any]]:
        """Activate related nodes when a new node is discovered."""
        activations: list[dict[str, Any]] = []

        # Type-specific activation patterns
        if node_type == "IPAddress":
            activations.extend(self._activate_ip(node_id, label))
        elif node_type == "Domain":
            activations.extend(self._activate_domain(node_id, label))
        elif node_type == "Subdomain":
            activations.extend(self._activate_subdomain(node_id, label))
        elif node_type == "Certificate":
            activations.extend(self._activate_certificate(node_id, label))
        elif node_type == "Credential":
            activations.extend(self._activate_credential(node_id, label))

        # General: activate nodes that share connections
        general = self._activate_shared_connections(node_id)
        activations.extend(general)

        # Store activations as memories
        for act in activations:
            if act["activation"] >= ACTIVATION_THRESHOLD:
                self._store_activation(act, node_id, node_type, label)

        if activations:
            logger.info(
                f"Spreading activation from [{node_type}] {label}: "
                f"{len(activations)} nodes activated"
            )

        return activations

    def _activate_ip(self, node_id: int, ip: str) -> list[dict[str, Any]]:
        """Activate nodes related to an IP address."""
        activations = []

        # Activate IPs in the same subnet
        parts = ip.split(".")
        if len(parts) == 4:
            prefix = ".".join(parts[:3]) + "."
            related = cypher_read(
                "MATCH (i:IPAddress) WHERE i.ip STARTS WITH $prefix AND id(i) <> $node_id "
                "RETURN id(i) AS id, i.ip AS label, 'IPAddress' AS type, 0.6 AS activation",
                {"prefix": prefix, "node_id": node_id},
            )
            for r in related:
                activations.append({
                    "node_id": r["id"],
                    "node_type": "IPAddress",
                    "label": r["label"],
                    "activation": r["activation"],
                    "reason": f"Same subnet as {ip}",
                    "hop": 1,
                })

            # Activate domains that resolve to nearby IPs
            domains = cypher_read(
                "MATCH (d:Domain)-[:RESOLVES_TO]->(i:IPAddress) "
                "WHERE i.ip STARTS WITH $prefix "
                "RETURN DISTINCT id(d) AS id, d.hostname AS label, 'Domain' AS type, 0.3 AS activation",
                {"prefix": prefix},
            )
            for r in domains:
                activations.append({
                    "node_id": r["id"],
                    "node_type": "Domain",
                    "label": r["label"],
                    "activation": r["activation"],
                    "reason": f"Domain resolving to subnet of {ip}",
                    "hop": 2,
                })

        return activations

    def _activate_domain(self, node_id: int, hostname: str) -> list[dict[str, Any]]:
        """Activate nodes related to a domain."""
        activations = []

        # Activate subdomains
        subs = cypher_read(
            "MATCH (d:Domain {hostname: $hostname})-[:HAS_SUBDOMAIN]->(s:Subdomain) "
            "RETURN id(s) AS id, s.name AS label, 'Subdomain' AS type, 0.7 AS activation",
            {"hostname": hostname},
        )
        for r in subs:
            activations.append({
                "node_id": r["id"],
                "node_type": "Subdomain",
                "label": r["label"],
                "activation": r["activation"],
                "reason": f"Subdomain of {hostname}",
                "hop": 1,
            })

        # Activate certificates for this domain
        certs = cypher_read(
            "MATCH (d:Domain {hostname: $hostname})-[:HAS_CERTIFICATE]->(c:Certificate) "
            "RETURN id(c) AS id, c.id AS label, 'Certificate' AS type, 0.5 AS activation",
            {"hostname": hostname},
        )
        for r in certs:
            activations.append({
                "node_id": r["id"],
                "node_type": "Certificate",
                "label": r["label"] or "cert",
                "activation": r["activation"],
                "reason": f"Certificate for {hostname}",
                "hop": 1,
            })

        # Activate domains with similar names (same root domain)
        root = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
        similar = cypher_read(
            "MATCH (d:Domain) WHERE d.hostname ENDS WITH $root AND d.hostname <> $hostname "
            "RETURN id(d) AS id, d.hostname AS label, 'Domain' AS type, 0.4 AS activation LIMIT 10",
            {"root": root, "hostname": hostname},
        )
        for r in similar:
            activations.append({
                "node_id": r["id"],
                "node_type": "Domain",
                "label": r["label"],
                "activation": r["activation"],
                "reason": f"Same root domain ({root})",
                "hop": 1,
            })

        return activations

    def _activate_subdomain(self, node_id: int, name: str) -> list[dict[str, Any]]:
        """Activate nodes related to a subdomain."""
        activations = []

        # Activate IPs this subdomain resolves to
        ips = cypher_read(
            "MATCH (s:Subdomain {name: $name})-[:RESOLVES_TO]->(i:IPAddress) "
            "RETURN id(i) AS id, i.ip AS label, 'IPAddress' AS type, 0.6 AS activation",
            {"name": name},
        )
        for r in ips:
            activations.append({
                "node_id": r["id"],
                "node_type": "IPAddress",
                "label": r["label"],
                "activation": r["activation"],
                "reason": f"IP for subdomain {name}",
                "hop": 1,
            })

        # Activate sibling subdomains
        parent = ".".join(name.split(".")[1:]) if "." in name else name
        if parent:
            siblings = cypher_read(
                "MATCH (d:Domain {hostname: $parent})-[:HAS_SUBDOMAIN]->(s:Subdomain) "
                "WHERE s.name <> $name "
                "RETURN id(s) AS id, s.name AS label, 'Subdomain' AS type, 0.4 AS activation LIMIT 20",
                {"parent": parent, "name": name},
            )
            for r in siblings:
                activations.append({
                    "node_id": r["id"],
                    "node_type": "Subdomain",
                    "label": r["label"],
                    "activation": r["activation"],
                    "reason": f"Sibling subdomain (parent: {parent})",
                    "hop": 1,
                })

        return activations

    def _activate_certificate(self, node_id: int, cert_id: str) -> list[dict[str, Any]]:
        """Activate nodes related to a certificate."""
        activations = []

        # Activate domains covered by this certificate
        domains = cypher_read(
            "MATCH (d:Domain)-[:HAS_CERTIFICATE]->(c:Certificate {id: $cert_id}) "
            "RETURN id(d) AS id, d.hostname AS label, 'Domain' AS type, 0.5 AS activation",
            {"cert_id": cert_id},
        )
        for r in domains:
            activations.append({
                "node_id": r["id"],
                "node_type": "Domain",
                "label": r["label"],
                "activation": r["activation"],
                "reason": f"Domain covered by certificate {cert_id}",
                "hop": 1,
            })

        return activations

    def _activate_credential(self, node_id: int, cred_id: str) -> list[dict[str, Any]]:
        """Activate nodes related to a credential."""
        activations = []

        # Activate other credentials with same email/domain
        if "@" in cred_id:
            domain = cred_id.split("@")[1]
            related = cypher_read(
                "MATCH (c:Credential) WHERE c.id CONTAINS $domain AND c.id <> $cred_id "
                "RETURN id(c) AS id, c.id AS label, 'Credential' AS type, 0.8 AS activation LIMIT 20",
                {"domain": domain, "cred_id": cred_id},
            )
            for r in related:
                activations.append({
                    "node_id": r["id"],
                    "node_type": "Credential",
                    "label": r["label"],
                    "activation": r["activation"],
                    "reason": f"Same email domain ({domain}) — possible credential reuse",
                    "hop": 1,
                })

        return activations

    def _activate_shared_connections(self, node_id: int) -> list[dict[str, Any]]:
        """Activate nodes that share connections with the source node."""
        activations = []

        # Find nodes that are 2 hops away and share a common neighbor
        shared = cypher_read(
            f"""
            MATCH (n)-[]-(common)-[]-(other)
            WHERE id(n) = $node_id AND id(other) <> $node_id
            WITH other, count(common) AS shared_count
            WHERE shared_count >= 2
            RETURN id(other) AS id, labels(other)[0] AS type,
                   coalesce(other.hostname, other.name, other.ip, other.id, 'unknown') AS label,
                   0.3 * shared_count AS activation, shared_count
            LIMIT 20
            """,
            {"node_id": node_id},
        )

        for r in shared:
            act = min(0.8, r["activation"])
            activations.append({
                "node_id": r["id"],
                "node_type": r["type"] or "Unknown",
                "label": r["label"],
                "activation": act,
                "reason": f"Shares {r['shared_count']} connections with source",
                "hop": 2,
            })

        return activations

    def _store_activation(
        self,
        activation: dict[str, Any],
        source_id: int,
        source_type: str,
        source_label: str,
    ) -> None:
        """Store an activation event as a cartographic memory."""
        cypher_write(
            "CREATE (m:Memory {id: $id}) "
            "SET m.memory_type = 'cartographic', m.content = $content, "
            "m.target = $target, m.severity = 'info', m.timestamp = datetime(), "
            "m.activation = $activation, m.activation_reason = $reason, "
            "m.source_node_id = $source_id, m.source_node_type = $source_type, "
            "m.source_node_label = $source_label, "
            "m.activated_node_id = $act_node_id, m.activated_node_type = $act_type, "
            "m.activated_node_label = $act_label",
            {
                "id": str(uuid.uuid4())[:12],
                "content": f"Activation: [{source_type}] {source_label} → [{activation['node_type']}] {activation['label']} (act={activation['activation']:.2f}, {activation['reason']})",
                "target": source_label,
                "activation": activation["activation"],
                "reason": activation["reason"],
                "source_id": source_id,
                "source_type": source_type,
                "source_label": source_label,
                "act_node_id": activation["node_id"],
                "act_type": activation["node_type"],
                "act_label": activation["label"],
            },
        )


# Singleton
spreading_activation = SpreadingActivation()