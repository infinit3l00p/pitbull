"""PITBULL Conference Watcher Scheduler — main orchestrator.

Coordinates conference tracking, arXiv paper monitoring, and knowledge base
updates. Can be called manually or scheduled via cron.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.conference_watcher.conferences import (
    CONFERENCE_DB,
    get_all_conferences,
    get_upcoming_conferences,
    update_conference_status,
)
from app.conference_watcher.paper_monitor import PaperMonitor, SECURITY_KEYWORDS
from app.conference_watcher.knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)


class ConferenceWatcher:
    """Main orchestrator for conference tracking, paper monitoring, and KB updates."""

    def __init__(self) -> None:
        self.paper_monitor = PaperMonitor()
        self.knowledge_base = KnowledgeBase()
        self._scan_in_progress = False

    async def run_full_scan(self) -> dict[str, Any]:
        """Run a complete scan: conferences + papers + knowledge base update.

        Returns a summary of new findings.
        """
        if self._scan_in_progress:
            logger.warning("Scan already in progress, skipping")
            return {"status": "skipped", "reason": "scan_in_progress"}

        self._scan_in_progress = True
        scan_id = datetime.now(timezone.utc).isoformat()
        logger.info("Conference Watcher full scan started at %s", scan_id)

        summary: dict[str, Any] = {
            "scan_id": scan_id,
            "conferences": {"total": 0, "upcoming": 0, "ongoing": 0, "past": 0},
            "papers": {"fetched": 0, "stored": 0, "errors": 0},
            "knowledge_base": {"entries_created": 0, "errors": 0},
            "errors": [],
        }

        try:
            # 1. Update conference statuses
            confs = update_conference_status()
            summary["conferences"]["total"] = len(confs)
            for c in confs:
                status = c.get("status", "upcoming")
                if status in summary["conferences"]:
                    summary["conferences"][status] += 1

            # 2. Check for new papers
            paper_results = await self.check_new_papers()
            summary["papers"] = paper_results

            # 3. Update knowledge base from new papers
            kb_results = await self.update_knowledge_base()
            summary["knowledge_base"] = kb_results

        except Exception as e:
            logger.error("Full scan error: %s", e)
            summary["errors"].append(str(e))
        finally:
            self._scan_in_progress = False

        logger.info("Conference Watcher full scan complete: %s", summary)
        return summary

    async def check_conference_updates(self) -> dict[str, Any]:
        """Check conference websites for new talks/schedules.

        Since conference data is hardcoded (websites change too frequently to
        scrape reliably), this returns the current status of all conferences
        and flags any that are starting soon (within 7 days).
        """
        update_conference_status()
        upcoming = get_upcoming_conferences(days=90)
        imminent = [c for c in upcoming if c.get("days_until", 999) <= 7]

        return {
            "total_tracked": len(CONFERENCE_DB),
            "upcoming": len(upcoming),
            "imminent": len(imminent),
            "imminent_conferences": [
                {"name": c["name"], "location": c["location"],
                 "start_date": c["start_date"], "days_until": c.get("days_until", 0),
                 "website": c["website"]}
                for c in imminent
            ],
        }

    async def check_new_papers(self, max_per_keyword: int = 5) -> dict[str, Any]:
        """Fetch new arXiv papers with security keywords.

        Scans all monitored keywords, stores unique papers in Neo4j.
        """
        result: dict[str, Any] = {
            "fetched": 0,
            "stored": 0,
            "errors": 0,
            "keywords_scanned": len(SECURITY_KEYWORDS),
        }

        try:
            papers = await self.paper_monitor.scan_keywords(max_per_keyword=max_per_keyword)
            result["fetched"] = len(papers)
            result["stored"] = len(papers)  # scan_keywords stores as it goes
        except Exception as e:
            logger.error("Paper scan error: %s", e)
            result["errors"] += 1
            result["error_detail"] = str(e)

        return result

    async def update_knowledge_base(self) -> dict[str, Any]:
        """Process new papers and extract knowledge entries.

        For each new paper, create a knowledge base entry summarizing the
        technique/research described.
        """
        result: dict[str, Any] = {"entries_created": 0, "errors": 0}

        try:
            # Get recent papers that haven't been processed into KB yet
            recent_papers = await self.paper_monitor.get_recent_papers(days=30)

            for paper in recent_papers:
                paper_id = paper.get("paper_id", "")
                title = paper.get("title", "")
                abstract = paper.get("abstract", "")

                # Skip if already has a KB entry
                existing = await self.knowledge_base.get_entries(
                    source=f"arxiv:{paper_id}", limit=1
                )
                if existing:
                    continue

                # Determine technique type from abstract keywords
                technique_type = self._classify_technique(title + " " + abstract)

                # Extract potential tags
                tags = self._extract_tags(title + " " + abstract)

                entry = {
                    "title": title,
                    "description": abstract[:2000] if abstract else "",
                    "source": f"arxiv:{paper_id}",
                    "source_url": paper.get("arxiv_url", ""),
                    "technique_type": technique_type,
                    "mitre_attack_ids": [],  # Would need NLP/LLM to extract properly
                    "tags": tags,
                    "relevance_score": 0.5,
                }

                created = await self.knowledge_base.add_entry(entry)
                if created:
                    result["entries_created"] += 1
                else:
                    result["errors"] += 1

        except Exception as e:
            logger.error("KB update error: %s", e)
            result["errors"] += 1
            result["error_detail"] = str(e)

        return result

    def _classify_technique(self, text: str) -> str:
        """Classify the technique type from paper text."""
        text_lower = text.lower()
        type_keywords = {
            "deception": ["deception", "honeypot", "decoy", "lure"],
            "fuzzing": ["fuzz", "fuzzing", "mutation", "test generation"],
            "exploitation": ["exploit", "vulnerability", "overflow", "injection", "rce"],
            "defense": ["defense", "detection", "prevention", "mitigation", "protection"],
            "ai_security": ["llm", "machine learning", "deep learning", "adversarial", "ai"],
            "hardware": ["hardware", "side channel", "fault injection", "fpga"],
            "crypto": ["cryptograph", "encryption", "cipher", "hash", "signature"],
            "malware": ["malware", "ransomware", "trojan", "botnet"],
            "network": ["network", "traffic", "ddos", "packet", "protocol"],
        }
        for tech_type, keywords in type_keywords.items():
            if any(kw in text_lower for kw in keywords):
                return tech_type
        return "general"

    def _extract_tags(self, text: str) -> list[str]:
        """Extract relevant tags from paper text."""
        text_lower = text.lower()
        tag_map = {
            "zero-day": ["zero-day", "zero day", "0day"],
            "vulnerability": ["vulnerability", "vuln", "cve"],
            "AI": ["llm", "ai", "machine learning", "deep learning"],
            "supply-chain": ["supply chain"],
            "intrusion-detection": ["intrusion detection", "ids"],
            "threat-intelligence": ["threat intel", "threat intelligence"],
            "binary-analysis": ["binary analysis", "reverse engineering"],
            "web-security": ["web", "xss", "sql injection", "csrf"],
            "mobile-security": ["mobile", "android", "ios"],
            "iot": ["iot", "embedded"],
            "cloud": ["cloud", "aws", "azure", "kubernetes"],
        }
        tags: list[str] = []
        for tag, keywords in tag_map.items():
            if any(kw in text_lower for kw in keywords):
                tags.append(tag)
        return tags if tags else ["general"]