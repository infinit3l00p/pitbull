"""PITBULL Paper Monitor — arXiv security paper tracker.

Monitors arXiv cs.CR category for new security research papers.
Rate limited: max 1 request per 3 seconds to respect arXiv API guidelines.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)

# arXiv API base
ARXIV_API = "http://export.arxiv.org/api/query"

# Security keywords to monitor
SECURITY_KEYWORDS: list[str] = [
    "deception",
    "honeypot",
    "fuzzing",
    "zero-day",
    "zero day",
    "vulnerability detection",
    "LLM security",
    "AI attacker",
    "cognitive warfare",
    "adversarial machine learning",
    "supply chain security",
    "hardware security",
    "side channel",
    "exploit",
    "ransomware",
    "intrusion detection",
    "threat intelligence",
    "malware analysis",
    "binary analysis",
    "program analysis",
]

# Rate limiting: minimum 3 seconds between requests
_MIN_INTERVAL = 3.0
_last_request_time: float = 0.0


class PaperMonitor:
    """Monitors arXiv for new security research papers."""

    def __init__(self) -> None:
        self.base_url = ARXIV_API
        self.keywords = SECURITY_KEYWORDS

    async def _rate_limited_get(self, url: str, client: httpx.AsyncClient) -> httpx.Response:
        """Make a rate-limited GET request to arXiv (max 1 per 3 seconds)."""
        global _last_request_time
        elapsed = time.monotonic() - _last_request_time
        if elapsed < _MIN_INTERVAL:
            wait = _MIN_INTERVAL - elapsed
            logger.debug("Rate limiting: waiting %.1fs before arXiv request", wait)
            await asyncio.sleep(wait)
        _last_request_time = time.monotonic()
        response = await client.get(url, timeout=30.0)
        response.raise_for_status()
        return response

    async def fetch_papers(self, query: str, max_results: int = 10) -> list[dict[str, Any]]:
        """Fetch papers from arXiv matching the query.

        Args:
            query: Search query (keyword or abstract search term).
            max_results: Maximum number of results to return.

        Returns:
            List of parsed paper dictionaries.
        """
        search_query = f"cat:cs.CR+AND+abs:{query}"
        url = (
            f"{self.base_url}?search_query={search_query}"
            f"&start=0&max_results={max_results}"
            f"&sortBy=submittedDate&sortOrder=descending"
        )

        async with httpx.AsyncClient() as client:
            try:
                response = await self._rate_limited_get(url, client)
                papers = self._parse_atom_feed(response.text)
                logger.info("Fetched %d papers from arXiv for query '%s'", len(papers), query)
                return papers
            except Exception as e:
                logger.error("Error fetching papers from arXiv: %s", e)
                return []

    def _parse_atom_feed(self, xml_text: str) -> list[dict[str, Any]]:
        """Parse arXiv Atom XML feed into paper dictionaries."""
        papers: list[dict[str, Any]] = []

        # arXiv uses Atom XML with namespaces
        ns = {
            "atom": "http://www.w3.org/2005/Atom",
            "arxiv": "http://arxiv.org/schemas/atom",
        }

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.error("Failed to parse arXiv XML: %s", e)
            return []

        for entry in root.findall("atom:entry", ns):
            paper = self._parse_paper(entry, ns)
            if paper:
                papers.append(paper)

        return papers

    def _parse_paper(self, entry: ET.Element, ns: dict[str, str]) -> dict[str, Any] | None:
        """Parse a single Atom entry into a paper dictionary.

        Extracts: title, authors, abstract, date, URL, categories, paper_id.
        """
        try:
            # Title
            title_elem = entry.find("atom:title", ns)
            title = title_elem.text.strip() if title_elem is not None and title_elem.text else ""
            # Clean whitespace
            title = " ".join(title.split())

            # Authors
            authors: list[str] = []
            for author in entry.findall("atom:author", ns):
                name_elem = author.find("atom:name", ns)
                if name_elem is not None and name_elem.text:
                    authors.append(name_elem.text.strip())

            # Abstract / Summary
            summary_elem = entry.find("atom:summary", ns)
            abstract = summary_elem.text.strip() if summary_elem is not None and summary_elem.text else ""
            abstract = " ".join(abstract.split())

            # Published date
            published_elem = entry.find("atom:published", ns)
            published_str = published_elem.text if published_elem is not None and published_elem.text else ""
            published_dt = None
            if published_str:
                try:
                    published_dt = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            # arXiv URL
            id_elem = entry.find("atom:id", ns)
            arxiv_url = id_elem.text.strip() if id_elem is not None and id_elem.text else ""

            # Paper ID (extract from URL: http://arxiv.org/abs/XXXX.XXXXX)
            paper_id = arxiv_url.split("/abs/")[-1] if "/abs/" in arxiv_url else arxiv_url

            # Categories
            categories: list[str] = []
            for category in entry.findall("atom:category", ns):
                term = category.get("term", "")
                if term:
                    categories.append(term)
            # Also check arxiv:primary_category
            primary_cat = entry.find("arxiv:primary_category", ns)
            if primary_cat is not None:
                primary_term = primary_cat.get("term", "")
                if primary_term and primary_term not in categories:
                    categories.insert(0, primary_term)

            # DOI (if available)
            doi_elem = entry.find("arxiv:doi", ns)
            doi = doi_elem.text.strip() if doi_elem is not None and doi_elem.text else None

            return {
                "paper_id": paper_id,
                "title": title,
                "authors": authors,
                "abstract": abstract,
                "published": published_dt.isoformat() if published_dt else "",
                "arxiv_url": arxiv_url,
                "doi": doi,
                "categories": categories,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.warning("Failed to parse paper entry: %s", e)
            return None

    async def store_paper(self, paper: dict[str, Any]) -> bool:
        """Store a paper in Neo4j as a :ResearchPaper node.

        Creates the node if it doesn't exist, updates if it does.
        """
        paper_id = paper.get("paper_id", str(uuid.uuid4()))
        query = """
        MERGE (r:ResearchPaper {paper_id: $paper_id})
        SET r.title = $title,
            r.authors = $authors,
            r.abstract = $abstract,
            r.published = $published,
            r.arxiv_url = $arxiv_url,
            r.doi = $doi,
            r.categories = $categories,
            r.fetched_at = $fetched_at
        RETURN r.paper_id AS paper_id
        """
        try:
            result = cypher_write(query, {
                "paper_id": paper_id,
                "title": paper.get("title", ""),
                "authors": paper.get("authors", []),
                "abstract": paper.get("abstract", ""),
                "published": paper.get("published", ""),
                "arxiv_url": paper.get("arxiv_url", ""),
                "doi": paper.get("doi"),
                "categories": paper.get("categories", []),
                "fetched_at": paper.get("fetched_at", datetime.now(timezone.utc).isoformat()),
            })
            return bool(result)
        except Exception as e:
            logger.error("Failed to store paper %s: %s", paper_id, e)
            return False

    async def get_recent_papers(self, days: int = 7) -> list[dict[str, Any]]:
        """Return papers from the last N days stored in Neo4j."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query = """
        MATCH (r:ResearchPaper)
        WHERE r.fetched_at >= $cutoff
        RETURN r.paper_id AS paper_id,
               r.title AS title,
               r.authors AS authors,
               r.abstract AS abstract,
               r.published AS published,
               r.arxiv_url AS arxiv_url,
               r.doi AS doi,
               r.categories AS categories,
               r.fetched_at AS fetched_at
        ORDER BY r.published DESC
        LIMIT 100
        """
        try:
            return cypher_read(query, {"cutoff": cutoff})
        except Exception as e:
            logger.error("Failed to get recent papers: %s", e)
            return []

    async def search_papers(self, query: str) -> list[dict[str, Any]]:
        """Full-text search across stored papers in Neo4j."""
        search_term = f"(?i).*{query}.*"
        cypher = """
        MATCH (r:ResearchPaper)
        WHERE r.title =~ $search_term
           OR r.abstract =~ $search_term
           OR ANY(author IN r.authors WHERE author =~ $search_term)
        RETURN r.paper_id AS paper_id,
               r.title AS title,
               r.authors AS authors,
               r.abstract AS abstract,
               r.published AS published,
               r.arxiv_url AS arxiv_url,
               r.doi AS doi,
               r.categories AS categories,
               r.fetched_at AS fetched_at
        ORDER BY r.published DESC
        LIMIT 50
        """
        try:
            return cypher_read(cypher, {"search_term": search_term})
        except Exception as e:
            logger.error("Failed to search papers: %s", e)
            return []

    async def scan_keywords(self, max_per_keyword: int = 5) -> list[dict[str, Any]]:
        """Scan arXiv for all monitored security keywords.

        Fetches papers for each keyword, stores them in Neo4j, and returns
        a summary of new papers found.
        """
        all_papers: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for keyword in self.keywords:
            papers = await self.fetch_papers(keyword, max_results=max_per_keyword)
            for paper in papers:
                pid = paper.get("paper_id", "")
                if pid and pid not in seen_ids:
                    seen_ids.add(pid)
                    await self.store_paper(paper)
                    all_papers.append(paper)

        logger.info("Scan complete: %d unique papers from %d keywords", len(all_papers), len(self.keywords))
        return all_papers