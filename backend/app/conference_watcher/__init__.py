"""PITBULL Conference Watcher — Asian hacking conference tracker.

Tracks Asian security conferences, monitors arXiv for new security research,
and maintains a knowledge base of techniques.
"""

from app.conference_watcher.conferences import (
    get_all_conferences,
    get_upcoming_conferences,
    get_conference,
    update_conference_status,
    CONFERENCE_DB,
)
from app.conference_watcher.paper_monitor import PaperMonitor
from app.conference_watcher.knowledge_base import KnowledgeBase
from app.conference_watcher.scheduler import ConferenceWatcher

__all__ = [
    "get_all_conferences",
    "get_upcoming_conferences",
    "get_conference",
    "update_conference_status",
    "CONFERENCE_DB",
    "PaperMonitor",
    "KnowledgeBase",
    "ConferenceWatcher",
]
from app.core.database import cypher_write

def init_neo4j_schema() -> None:
    """Initialize Neo4j schema for Conference Watcher."""
    cypher_write("CREATE CONSTRAINT research_paper_id IF NOT EXISTS FOR (r:ResearchPaper) REQUIRE r.paper_id IS UNIQUE")
    cypher_write("CREATE CONSTRAINT knowledge_entry_id IF NOT EXISTS FOR (k:KnowledgeEntry) REQUIRE k.entry_id IS UNIQUE")
