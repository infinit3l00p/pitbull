"""PITBULL Forensic Reconstruction — timeline and infrastructure genealogy.

Reconstructs historical timelines from all collected data and traces
infrastructure connections across time.

Academic basis:
- Spoor (2026): autonomous DFIR with timeline reconstruction
- TORONS (IEEE 2026): network cartography
- SYNAPSE (ACL 2026): spreading activation for serendipitous connections
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from app.core.database import cypher_read

logger = logging.getLogger(__name__)


class ForensicReconstructor:
    """Reconstructs timelines and infrastructure genealogy from Neo4j data."""

    def build_timeline(self, target: str) -> dict[str, Any]:
        """Build a forensic timeline for a target domain."""
        events: list[dict[str, Any]] = []

        # Domain creation/update from WHOIS
        whois_events = cypher_read(
            "MATCH (d:Domain {hostname: $target}) "
            "WHERE d.creation_date IS NOT NULL OR d.expiry_date IS NOT NULL "
            "RETURN d.creation_date AS creation, d.expiry_date AS expiry, d.registrar AS registrar",
            {"target": target},
        )
        for row in whois_events:
            if row.get("creation"):
                events.append({
                    "date": str(row["creation"]),
                    "event": "Domain registered",
                    "source": "WHOIS",
                    "details": f"Registrar: {row.get('registrar', 'unknown')}",
                })
            if row.get("expiry"):
                events.append({
                    "date": str(row["expiry"]),
                    "event": "Domain registration expires",
                    "source": "WHOIS",
                    "details": f"Registrar: {row.get('registrar', 'unknown')}",
                })

        # Certificate timeline
        cert_events = cypher_read(
            "MATCH (d:Domain {hostname: $target})-[:HAS_CERTIFICATE]->(c:Certificate) "
            "WHERE c.not_before IS NOT NULL "
            "RETURN c.not_before AS not_before, c.not_after AS not_after, "
            "c.issuer AS issuer, c.common_name AS cn, c.id AS cert_id",
            {"target": target},
        )
        for row in cert_events:
            if row.get("not_before"):
                events.append({
                    "date": str(row["not_before"]),
                    "event": "Certificate issued",
                    "source": "Certificate Transparency",
                    "details": f"Issuer: {row.get('issuer', '')}, CN: {row.get('cn', '')}",
                })
            if row.get("not_after"):
                events.append({
                    "date": str(row["not_after"]),
                    "event": "Certificate expires",
                    "source": "Certificate Transparency",
                    "details": f"Issuer: {row.get('issuer', '')}",
                })

        # Subdomain discovery timeline
        sub_events = cypher_read(
            "MATCH (d:Domain {hostname: $target})-[:HAS_SUBDOMAIN]->(s:Subdomain) "
            "RETURN s.name AS name, s.first_seen AS first_seen, s.last_seen AS last_seen "
            "ORDER BY s.first_seen",
            {"target": target},
        )
        for row in sub_events:
            if row.get("first_seen"):
                events.append({
                    "date": str(row["first_seen"]),
                    "event": "Subdomain discovered",
                    "source": "DNS Recon",
                    "details": f"Subdomain: {row.get('name', '')}",
                })

        # IP resolution timeline
        ip_events = cypher_read(
            "MATCH (d:Domain {hostname: $target})-[:RESOLVES_TO]->(i:IPAddress) "
            "RETURN i.ip AS ip, i.first_seen AS first_seen, i.last_seen AS last_seen, "
            "i.asn AS asn, i.country AS country "
            "ORDER BY i.first_seen",
            {"target": target},
        )
        for row in ip_events:
            if row.get("first_seen"):
                events.append({
                    "date": str(row["first_seen"]),
                    "event": "IP resolution",
                    "source": "DNS Recon",
                    "details": f"IP: {row.get('ip', '')}, ASN: {row.get('asn', '')}, Country: {row.get('country', '')}",
                })

        # Episodic memory timeline (crawl events, etc.)
        memory_events = cypher_read(
            "MATCH (m:Memory) WHERE m.target CONTAINS $target AND m.timestamp IS NOT NULL "
            "RETURN m.timestamp AS ts, m.content AS content, m.memory_type AS type, m.severity AS severity "
            "ORDER BY m.timestamp",
            {"target": target},
        )
        for row in memory_events:
            if row.get("ts"):
                events.append({
                    "date": str(row["ts"]),
                    "event": f"[{row.get('type', 'memory')}] {row.get('content', '')[:100]}",
                    "source": "PITBULL Memory",
                    "severity": row.get("severity", "info"),
                })

        # Sort by date
        events.sort(key=lambda x: x.get("date", ""))

        return {
            "target": target,
            "events": events,
            "count": len(events),
            "first_event": events[0] if events else None,
            "last_event": events[-1] if events else None,
        }

    def infrastructure_genealogy(self, target: str, max_depth: int = 3) -> dict[str, Any]:
        """Trace infrastructure connections across time and targets."""
        connections: list[dict[str, Any]] = []

        # 1. Shared IPs — domains that resolve to the same IPs as target
        shared_ips = cypher_read(
            """
            MATCH (d:Domain {hostname: $target})-[:RESOLVES_TO]->(i:IPAddress)<-[:RESOLVES_TO]-(other:Domain)
            WHERE other.hostname <> $target
            RETURN DISTINCT other.hostname AS domain, collect(i.ip) AS shared_ips
            LIMIT 20
            """,
            {"target": target},
        )
        for row in shared_ips:
            connections.append({
                "type": "shared_ip",
                "from": target,
                "to": row.get("domain", ""),
                "evidence": row.get("shared_ips", []),
                "description": f"Shares IP addresses with {row.get('domain', '')}",
            })

        # 2. Shared certificates — domains covered by same certificates
        shared_certs = cypher_read(
            """
            MATCH (d:Domain {hostname: $target})-[:HAS_CERTIFICATE]->(c:Certificate)<-[:HAS_CERTIFICATE]-(other:Domain)
            WHERE other.hostname <> $target
            RETURN DISTINCT other.hostname AS domain, count(c) AS shared_cert_count
            ORDER BY shared_cert_count DESC
            LIMIT 20
            """,
            {"target": target},
        )
        for row in shared_certs:
            connections.append({
                "type": "shared_certificate",
                "from": target,
                "to": row.get("domain", ""),
                "evidence": f"{row.get('shared_cert_count', 0)} shared certificates",
                "description": f"Shares {row.get('shared_cert_count', 0)} certificates with {row.get('domain', '')}",
            })

        # 3. Same subnet neighbors
        subnet_neighbors = cypher_read(
            """
            MATCH (d:Domain {hostname: $target})-[:RESOLVES_TO]->(i:IPAddress)
            WITH split(i.ip, '.')[0] + '.' + split(i.ip, '.')[1] + '.' + split(i.ip, '.')[2] AS subnet
            MATCH (other:Domain)-[:RESOLVES_TO]->(nearby:IPAddress)
            WHERE nearby.ip STARTS WITH subnet + '.'
            AND other.hostname <> $target
            RETURN DISTINCT other.hostname AS domain, collect(nearby.ip) AS ips
            LIMIT 20
            """,
            {"target": target},
        )
        for row in subnet_neighbors:
            connections.append({
                "type": "same_subnet",
                "from": target,
                "to": row.get("domain", ""),
                "evidence": row.get("ips", []),
                "description": f"Located in same subnet as {row.get('domain', '')}",
            })

        # 4. Shared certificate issuer
        shared_issuer = cypher_read(
            """
            MATCH (d:Domain {hostname: $target})-[:HAS_CERTIFICATE]->(c:Certificate)
            WITH c.issuer AS issuer
            MATCH (other:Domain)-[:HAS_CERTIFICATE]->(c2:Certificate {issuer: issuer})
            WHERE other.hostname <> $target
            RETURN DISTINCT other.hostname AS domain, issuer, count(*) AS cert_count
            ORDER BY cert_count DESC
            LIMIT 20
            """,
            {"target": target},
        )
        for row in shared_issuer:
            connections.append({
                "type": "shared_issuer",
                "from": target,
                "to": row.get("domain", ""),
                "evidence": f"Issuer: {row.get('issuer', '')}, {row.get('cert_count', 0)} certs",
                "description": f"Shares certificate issuer ({row.get('issuer', '')}) with {row.get('domain', '')}",
            })

        # 5. Subdomain overlaps — domains that share subdomain names
        shared_subs = cypher_read(
            """
            MATCH (d:Domain {hostname: $target})-[:HAS_SUBDOMAIN]->(s:Subdomain)
            WITH s.name AS subname, split(s.name, '.')[0] AS prefix
            MATCH (other:Domain)-[:HAS_SUBDOMAIN]->(s2:Subdomain)
            WHERE split(s2.name, '.')[0] = prefix
            AND other.hostname <> $target
            RETURN DISTINCT other.hostname AS domain, collect(DISTINCT prefix) AS shared_prefixes
            LIMIT 20
            """,
            {"target": target},
        )
        for row in shared_subs:
            connections.append({
                "type": "shared_subdomain_pattern",
                "from": target,
                "to": row.get("domain", ""),
                "evidence": row.get("shared_prefixes", []),
                "description": f"Shares subdomain naming patterns with {row.get('domain', '')}",
            })

        return {
            "target": target,
            "connections": connections,
            "count": len(connections),
            "depth": max_depth,
            "connection_types": list(set(c["type"] for c in connections)),
        }

    def attribution_analysis(self, target: str) -> dict[str, Any]:
        """Analyze potential attribution indicators."""
        indicators: list[dict[str, Any]] = []

        # Registrant info
        whois_data = cypher_read(
            "MATCH (d:Domain {hostname: $target}) RETURN d.registrar AS registrar, "
            "d.registrant_email AS email, d.registrant_org AS org",
            {"target": target},
        )
        for row in whois_data:
            if row.get("email"):
                indicators.append({
                    "type": "registrant_email",
                    "value": row["email"],
                    "confidence": 0.8,
                })
            if row.get("org"):
                indicators.append({
                    "type": "registrant_org",
                    "value": row["org"],
                    "confidence": 0.7,
                })

        # Certificate common names
        cert_data = cypher_read(
            "MATCH (d:Domain {hostname: $target})-[:HAS_CERTIFICATE]->(c:Certificate) "
            "RETURN c.common_name AS cn, c.issuer AS issuer, c.id AS cert_id "
            "LIMIT 20",
            {"target": target},
        )
        for row in cert_data:
            if row.get("cn") and row["cn"] != target:
                indicators.append({
                    "type": "cert_common_name",
                    "value": row["cn"],
                    "confidence": 0.6,
                    "details": f"Certificate CN differs from domain",
                })

        return {
            "target": target,
            "indicators": indicators,
            "count": len(indicators),
        }


forensic_reconstructor = ForensicReconstructor()