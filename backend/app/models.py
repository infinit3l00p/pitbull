"""PITBULL models — Pydantic models for entities and relationships."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── Node Models ────────────────────────────────────────────────────

class Domain(BaseModel):
    hostname: str
    root_domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiry_date: str = ""
    name_servers: list[str] = Field(default_factory=list)
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    tags: list[str] = Field(default_factory=list)


class Subdomain(BaseModel):
    name: str
    parent_domain: str = ""
    is_wildcard: bool = False
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    tags: list[str] = Field(default_factory=list)


class IPAddress(BaseModel):
    ip: str
    asn: str = ""
    country: str = ""
    city: str = ""
    isp: str = ""
    is_cloud: bool = False
    cloud_provider: str = ""
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    tags: list[str] = Field(default_factory=list)


class Port(BaseModel):
    ip_id: str = ""
    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    banner: str = ""
    service_type: str = ""
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)


class Service(BaseModel):
    id: str
    name: str = ""
    version: str = ""
    product: str = ""
    cpe: str = ""
    os_type: str = ""
    banner_raw: str = ""
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)


class CVE(BaseModel):
    cve_id: str
    description: str = ""
    cvss_v3_score: float = 0.0
    severity: str = ""
    published_date: str = ""
    modified_date: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)


class OnionService(BaseModel):
    address: str
    title: str = ""
    service_type: str = ""
    is_online: bool = True
    pgp_key: str = ""
    last_checked: datetime = Field(default_factory=datetime.now)
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)


class Certificate(BaseModel):
    serial: str = ""
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    fingerprint_sha256: str = ""
    fingerprint_md5: str = ""
    is_expired: bool = False
    is_self_signed: bool = False
    covers_domains: list[str] = Field(default_factory=list)
    source: str = "pitbull"
    first_seen: datetime = Field(default_factory=datetime.now)


class Memory(BaseModel):
    id: str
    memory_type: str = "episodic"  # episodic, semantic, procedural, cartographic
    content: str = ""
    target: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    confidence: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)
    context: dict[str, Any] = Field(default_factory=dict)


# ── Request/Response Models ───────────────────────────────────────

class ExploreRequest(BaseModel):
    target: str = Field(..., description="Target domain or URL to explore")
    depth: int = Field(default=2, ge=1, le=5, description="Exploration depth")
    scope: str = Field(default="surface", description="surface, deep, darknet, full")
    rate_limit_ms: int = Field(default=500, ge=100, le=5000)


class ExploreResponse(BaseModel):
    exploration_id: str
    target: str
    status: str = "started"
    discoveries: int = 0
    message: str = ""


class GraphData(BaseModel):
    nodes: list[dict] = Field(default_factory=list)
    edges: list[dict] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    neo4j: dict[str, Any] = Field(default_factory=dict)


class PersonalityState(BaseModel):
    openness: float = 0.7
    conscientiousness: float = 0.6
    extraversion: float = 0.5
    agreeableness: float = 0.4
    neuroticism: float = 0.3
    mood: str = "neutral"
    mood_expires: datetime | None = None
    opinions: list[dict[str, Any]] = Field(default_factory=list)
    missions_completed: int = 0
    findings_total: int = 0
    false_positives: int = 0
    mistakes_learned: int = 0