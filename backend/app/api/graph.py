"""PITBULL API — graph and memory endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)

router = APIRouter(tags=["graph"])


@router.get("/full")
async def get_full_graph(limit: int = 500) -> dict[str, Any]:
    """Get the full memory graph for visualization."""
    nodes_result = cypher_read(
        "MATCH (n) WHERE n:Domain OR n:Subdomain OR n:IPAddress OR n:Certificate OR n:Memory "
        "RETURN id(n) AS id, labels(n) AS labels, properties(n) AS props "
        f"LIMIT {limit}"
    )

    edges_result = cypher_read(
        "MATCH (a)-[r]->(b) "
        "WHERE (a:Domain OR a:Subdomain OR a:IPAddress) "
        "AND (b:Domain OR b:Subdomain OR b:IPAddress OR b:Certificate) "
        f"RETURN id(a) AS source, id(b) AS target, type(r) AS rel_type "
        f"LIMIT {limit}"
    )

    nodes = []
    for row in nodes_result:
        labels = row.get("labels", [])
        props = row.get("props", {})
        node_type = labels[0] if labels else "Unknown"

        label = (
            props.get("hostname", "")
            or props.get("name", "")
            or props.get("ip", "")
            or props.get("content", "")[:50]
            or f"Node {row.get('id')}"
        )

        nodes.append({
            "id": row.get("id"),
            "type": node_type,
            "label": label,
            "props": {k: str(v)[:100] for k, v in props.items()},
        })

    edges = [
        {
            "source": row.get("source"),
            "target": row.get("target"),
            "type": row.get("rel_type", ""),
        }
        for row in edges_result
    ]

    return {"nodes": nodes, "edges": edges}


@router.get("/stats")
async def get_graph_stats() -> dict[str, Any]:
    """Get statistics about the memory graph."""
    stats = {}

    for label in ["Domain", "Subdomain", "IPAddress", "Certificate", "Memory", "OnionService", "CVE"]:
        result = cypher_read(f"MATCH (n:{label}) RETURN count(n) AS count")
        stats[label.lower()] = result[0]["count"] if result else 0

    edge_result = cypher_read("MATCH ()-[r]->() RETURN count(r) AS count")
    stats["total_edges"] = edge_result[0]["count"] if edge_result else 0

    return stats


@router.get("/memories")
async def get_memories(limit: int = 50, memory_type: str | None = None) -> dict[str, Any]:
    """Get episodic/semantic memories."""
    if memory_type:
        result = cypher_read(
            "MATCH (m:Memory {memory_type: $type}) "
            "RETURN m ORDER BY m.timestamp DESC LIMIT $limit",
            {"type": memory_type, "limit": limit},
        )
    else:
        result = cypher_read(
            "MATCH (m:Memory) RETURN m ORDER BY m.timestamp DESC LIMIT $limit",
            {"limit": limit},
        )

    memories = []
    for row in result:
        m = row.get("m", {})
        memories.append({
            "id": m.get("id", ""),
            "type": m.get("memory_type", "episodic"),
            "content": m.get("content", ""),
            "target": m.get("target", ""),
            "severity": m.get("severity", "info"),
            "timestamp": str(m.get("timestamp", "")),
        })

    return {"memories": memories, "count": len(memories)}


@router.delete("/clear")
async def clear_graph(confirm: str = "") -> dict[str, Any]:
    """Clear all nodes and edges.

    Requires ?confirm=DELETE_EVERYTHING to prevent accidental wipes.
    This is a destructive operation — the watchdog cannot recover from it.
    """
    if confirm != "DELETE_EVERYTHING":
        return {
            "status": "rejected",
            "error": "Confirmation required: pass ?confirm=DELETE_EVERYTHING to proceed",
            "hint": "This endpoint wipes ALL Neo4j data. Be certain you want this.",
        }
    cypher_write("MATCH (n) DETACH DELETE n")
    logger.warning("Graph cleared by explicit request — all nodes deleted")
    return {"status": "cleared", "confirm": confirm}