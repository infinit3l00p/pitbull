"""PITBULL Neo4j connection and schema management."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any

from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable

from app.config import settings

logger = logging.getLogger(__name__)

_driver: Driver | None = None


def get_driver() -> Driver:
    """Get or create the Neo4j driver singleton."""
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
    return _driver


def close_driver() -> None:
    """Close the Neo4j driver."""
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


def test_connection() -> bool:
    """Test the Neo4j connection."""
    try:
        with get_driver().session() as session:
            result = session.run("RETURN 1 AS test")
            return result.single()["test"] == 1
    except ServiceUnavailable:
        return False
    except Exception as e:
        logger.error(f"Neo4j connection error: {e}")
        return False


@contextmanager
def session():
    """Context manager for a Neo4j session."""
    s = get_driver().session()
    try:
        yield s
    finally:
        s.close()


def init_schema() -> None:
    """Initialize Neo4j schema with constraints and indexes."""
    constraints = [
        "CREATE CONSTRAINT domain_hostname IF NOT EXISTS FOR (d:Domain) REQUIRE d.hostname IS UNIQUE",
        "CREATE CONSTRAINT subdomain_name IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE",
        "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.ip IS UNIQUE",
        "CREATE CONSTRAINT port_unique IF NOT EXISTS FOR (p:Port) REQUIRE (p.ip_id, p.port_number, p.protocol) IS UNIQUE",
        "CREATE CONSTRAINT service_unique IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
        "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
        "CREATE CONSTRAINT onion_addr IF NOT EXISTS FOR (o:OnionService) REQUIRE o.address IS UNIQUE",
        "CREATE CONSTRAINT cert_fingerprint IF NOT EXISTS FOR (c:Certificate) REQUIRE c.fingerprint_sha256 IS UNIQUE",
        "CREATE CONSTRAINT person_email IF NOT EXISTS FOR (p:Person) REQUIRE p.email IS UNIQUE",
        "CREATE CONSTRAINT cred_unique IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
        "CREATE CONSTRAINT org_name IF NOT EXISTS FOR (o:Organization) REQUIRE o.name IS UNIQUE",
        "CREATE CONSTRAINT memory_id IF NOT EXISTS FOR (m:Memory) REQUIRE m.id IS UNIQUE",
        "CREATE CONSTRAINT opinion_subject IF NOT EXISTS FOR (o:Opinion) REQUIRE o.subject IS UNIQUE",
        "CREATE CONSTRAINT semantic_subject IF NOT EXISTS FOR (m:Memory) WHERE m.memory_type = 'semantic' REQUIRE m.subject IS UNIQUE",
    ]

    indexes = [
        "CREATE INDEX domain_root IF NOT EXISTS FOR (d:Domain) ON (d.root_domain)",
        "CREATE INDEX ip_asn IF NOT EXISTS FOR (i:IPAddress) ON (i.asn)",
        "CREATE INDEX ip_country IF NOT EXISTS FOR (i:IPAddress) ON (i.country)",
        "CREATE INDEX service_type IF NOT EXISTS FOR (s:Service) ON (s.service_type)",
        "CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity)",
        "CREATE INDEX memory_type IF NOT EXISTS FOR (m:Memory) ON (m.memory_type)",
        "CREATE INDEX memory_timestamp IF NOT EXISTS FOR (m:Memory) ON (m.timestamp)",
        "CREATE INDEX node_first_seen IF NOT EXISTS FOR (n:Node) ON (n.first_seen)",
        "CREATE INDEX node_last_seen IF NOT EXISTS FOR (n:Node) ON (n.last_seen)",
    ]

    with session() as s:
        for stmt in constraints:
            try:
                s.run(stmt)
            except Exception as e:
                logger.debug(f"Constraint skipped (may already exist): {e}")
        for stmt in indexes:
            try:
                s.run(stmt)
            except Exception as e:
                logger.debug(f"Index skipped (may already exist): {e}")
        logger.info("Neo4j schema initialized: %d constraints, %d indexes", len(constraints), len(indexes))


def cypher_write(query: str, params: dict[str, Any] | None = None) -> list[dict]:
    """Execute a write query and return records."""
    with session() as s:
        result = s.run(query, params or {})
        return [r.data() for r in result]


def cypher_read(query: str, params: dict[str, Any] | None = None) -> list[dict]:
    """Execute a read query and return records."""
    with session() as s:
        result = s.run(query, params or {})
        return [r.data() for r in result]