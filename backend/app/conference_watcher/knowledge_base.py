"""PITBULL Knowledge Base — security techniques knowledge store.

Maintains a knowledge base of techniques learned from conferences and papers.
Stores entries in Neo4j as :KnowledgeEntry nodes.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Manages a knowledge base of security techniques in Neo4j."""

    def __init__(self) -> None:
        pass

    async def add_entry(self, entry: dict[str, Any]) -> dict[str, Any] | None:
        """Add a new knowledge entry to the knowledge base.

        Expected entry fields:
            title, description, source, source_url, technique_type,
            mitre_attack_ids, tags, relevance_score
        """
        entry_id = entry.get("entry_id", str(uuid.uuid4()))
        now = datetime.now(timezone.utc).isoformat()

        query = """
        MERGE (k:KnowledgeEntry {entry_id: $entry_id})
        SET k.title = $title,
            k.description = $description,
            k.source = $source,
            k.source_url = $source_url,
            k.technique_type = $technique_type,
            k.mitre_attack_ids = $mitre_attack_ids,
            k.tags = $tags,
            k.relevance_score = $relevance_score,
            k.added_at = $added_at
        RETURN k.entry_id AS entry_id, k.title AS title
        """
        try:
            result = cypher_write(query, {
                "entry_id": entry_id,
                "title": entry.get("title", ""),
                "description": entry.get("description", ""),
                "source": entry.get("source", ""),
                "source_url": entry.get("source_url", ""),
                "technique_type": entry.get("technique_type", "general"),
                "mitre_attack_ids": entry.get("mitre_attack_ids", []),
                "tags": entry.get("tags", []),
                "relevance_score": entry.get("relevance_score", 0.5),
                "added_at": entry.get("added_at", now),
            })
            if result:
                logger.info("Added knowledge entry: %s — %s", entry_id, entry.get("title", ""))
                return result[0]
            return None
        except Exception as e:
            logger.error("Failed to add knowledge entry: %s", e)
            return None

    async def get_entries(
        self,
        technique_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query knowledge base entries with optional filters."""
        conditions: list[str] = []
        params: dict[str, Any] = {"limit": limit, "offset": offset}

        if technique_type:
            conditions.append("k.technique_type = $technique_type")
            params["technique_type"] = technique_type

        if source:
            conditions.append("k.source = $source")
            params["source"] = source

        if tag:
            conditions.append("$tag IN k.tags")
            params["tag"] = tag

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
        MATCH (k:KnowledgeEntry)
        {where_clause}
        RETURN k.entry_id AS entry_id,
               k.title AS title,
               k.description AS description,
               k.source AS source,
               k.source_url AS source_url,
               k.technique_type AS technique_type,
               k.mitre_attack_ids AS mitre_attack_ids,
               k.tags AS tags,
               k.relevance_score AS relevance_score,
               k.added_at AS added_at
        ORDER BY k.added_at DESC
        SKIP $offset
        LIMIT $limit
        """
        try:
            return cypher_read(query, params)
        except Exception as e:
            logger.error("Failed to get knowledge entries: %s", e)
            return []

    async def search_entries(self, query: str) -> list[dict[str, Any]]:
        """Semantic search across the knowledge base.

        Searches title, description, and tags for the query term.
        """
        search_term = f"(?i).*{query}.*"
        cypher = """
        MATCH (k:KnowledgeEntry)
        WHERE k.title =~ $search_term
           OR k.description =~ $search_term
           OR ANY(tag IN k.tags WHERE tag =~ $search_term)
        RETURN k.entry_id AS entry_id,
               k.title AS title,
               k.description AS description,
               k.source AS source,
               k.source_url AS source_url,
               k.technique_type AS technique_type,
               k.mitre_attack_ids AS mitre_attack_ids,
               k.tags AS tags,
               k.relevance_score AS relevance_score,
               k.added_at AS added_at
        ORDER BY k.relevance_score DESC, k.added_at DESC
        LIMIT 50
        """
        try:
            return cypher_read(cypher, {"search_term": search_term})
        except Exception as e:
            logger.error("Failed to search knowledge base: %s", e)
            return []

    async def get_by_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Get entries related to a specific MITRE ATT&CK technique."""
        cypher = """
        MATCH (k:KnowledgeEntry)
        WHERE $technique_id IN k.mitre_attack_ids
        RETURN k.entry_id AS entry_id,
               k.title AS title,
               k.description AS description,
               k.source AS source,
               k.source_url AS source_url,
               k.technique_type AS technique_type,
               k.mitre_attack_ids AS mitre_attack_ids,
               k.tags AS tags,
               k.relevance_score AS relevance_score,
               k.added_at AS added_at
        ORDER BY k.relevance_score DESC
        """
        try:
            return cypher_read(cypher, {"technique_id": technique_id})
        except Exception as e:
            logger.error("Failed to get entries by technique %s: %s", technique_id, e)
            return []

    async def get_entry(self, entry_id: str) -> dict[str, Any] | None:
        """Get a specific knowledge entry by ID."""
        cypher = """
        MATCH (k:KnowledgeEntry {entry_id: $entry_id})
        RETURN k.entry_id AS entry_id,
               k.title AS title,
               k.description AS description,
               k.source AS source,
               k.source_url AS source_url,
               k.technique_type AS technique_type,
               k.mitre_attack_ids AS mitre_attack_ids,
               k.tags AS tags,
               k.relevance_score AS relevance_score,
               k.added_at AS added_at
        """
        try:
            results = cypher_read(cypher, {"entry_id": entry_id})
            return results[0] if results else None
        except Exception as e:
            logger.error("Failed to get knowledge entry %s: %s", entry_id, e)
            return None

    async def update_relevance(self, entry_id: str, score: float) -> bool:
        """Update the relevance score of a knowledge entry."""
        cypher = """
        MATCH (k:KnowledgeEntry {entry_id: $entry_id})
        SET k.relevance_score = $score
        RETURN k.entry_id AS entry_id, k.relevance_score AS relevance_score
        """
        try:
            result = cypher_write(cypher, {"entry_id": entry_id, "score": score})
            return bool(result)
        except Exception as e:
            logger.error("Failed to update relevance for %s: %s", entry_id, e)
            return False

    async def export_kb(self, fmt: str = "json") -> str:
        """Export the entire knowledge base in JSON or markdown format."""
        entries = await self.get_entries(limit=10000)
        if fmt == "markdown":
            return self._export_markdown(entries)
        return json.dumps(entries, indent=2, ensure_ascii=False)

    def _export_markdown(self, entries: list[dict[str, Any]]) -> str:
        """Format knowledge base entries as markdown."""
        lines: list[str] = ["# PITBULL Knowledge Base Export", ""]
        lines.append(f"**Total entries:** {len(entries)}")
        lines.append(f"**Exported:** {datetime.now(timezone.utc).isoformat()}")
        lines.append("")
        for entry in entries:
            lines.append(f"## {entry.get('title', 'Untitled')}")
            lines.append("")
            lines.append(f"- **ID:** {entry.get('entry_id', '')}")
            lines.append(f"- **Type:** {entry.get('technique_type', '')}")
            lines.append(f"- **Source:** {entry.get('source', '')}")
            if entry.get("source_url"):
                lines.append(f"- **URL:** {entry.get('source_url')}")
            if entry.get("mitre_attack_ids"):
                lines.append(f"- **MITRE ATT&CK:** {', '.join(entry['mitre_attack_ids'])}")
            if entry.get("tags"):
                lines.append(f"- **Tags:** {', '.join(entry['tags'])}")
            lines.append(f"- **Relevance:** {entry.get('relevance_score', 0)}")
            lines.append(f"- **Added:** {entry.get('added_at', '')}")
            lines.append("")
            lines.append(entry.get("description", ""))
            lines.append("")
            lines.append("---")
            lines.append("")
        return "\n".join(lines)

    async def get_stats(self) -> dict[str, Any]:
        """Get knowledge base statistics."""
        cypher = """
        MATCH (k:KnowledgeEntry)
        RETURN count(k) AS total,
               collect(DISTINCT k.technique_type) AS types,
               collect(DISTINCT k.source) AS sources
        """
        try:
            results = cypher_read(cypher)
            if results:
                return results[0]
            return {"total": 0, "types": [], "sources": []}
        except Exception as e:
            logger.error("Failed to get KB stats: %s", e)
            return {"total": 0, "types": [], "sources": []}