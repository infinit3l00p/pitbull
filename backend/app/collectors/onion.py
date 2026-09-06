"""Onion service discovery and classification.

Discovers .onion addresses from multiple sources and classifies them
by type (marketplace, forum, blog, etc.).

Academic basis:
- Mimir Crawler (IEEE TIFS 2025): snorkeling approach for .onion exploration
- ONIONTRACEX (2026): onion service classification taxonomy
- TORONS (IEEE 2026): mapping the unseen web
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from app.collectors.tor import tor_controller

logger = logging.getLogger(__name__)

# .onion address regex (v2 = 16 chars, v3 = 56 chars)
ONION_REGEX = re.compile(r"[a-z2-7]{16,56}\.onion", re.IGNORECASE)

# Service classification taxonomy (from ONIONTRACEX)
SERVICE_TYPES = {
    "marketplace": ["market", "shop", "store", "vendor", "drug", "weed", "pill"],
    "forum": ["forum", "board", "community", "discussion", "chat"],
    "blog": ["blog", "news", "article", "post", "journal"],
    "communication": ["email", "mail", "messaging", "chat", "signal", "telegram"],
    "cryptocurrency": ["bitcoin", "crypto", "wallet", "exchange", "mixer", "tumbler"],
    "whistleblowing": ["leak", "whistle", "secure", "drop", "source"],
    "file_sharing": ["file", "upload", "download", "share", "paste", "bin"],
    "illegal_services": ["hitman", "weapon", "counterfeit", "carding", "fraud"],
    "infrastructure": ["directory", "search", "engine", "index", "list"],
    "security_research": ["security", "research", "exploit", "vuln", "pentest"],
}


class OnionCollector:
    """Discovers and classifies .onion services."""

    def __init__(self):
        self.discovered_onions: set[str] = set()

    async def discover_from_ahmia(self, query: str = "") -> list[str]:
        """Discover .onion services from Ahmia directory (clearnet)."""
        onions: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = "https://ahmia.fi/search/" if not query else f"https://ahmia.fi/search/?q={query}"
                resp = await client.get(url)
                if resp.status_code == 200:
                    found = ONION_REGEX.findall(resp.text)
                    onions = list(set(found))
                    logger.info(f"Ahmia: found {len(onions)} .onion addresses")
        except Exception as e:
            logger.warning(f"Ahmia discovery failed: {e}")
        return onions

    async def discover_from_text(self, text: str) -> list[str]:
        """Extract .onion addresses from any text (web pages, forums, etc.)."""
        found = ONION_REGEX.findall(text)
        return list(set(found))

    async def discover_from_url(self, url: str) -> list[str]:
        """Fetch a URL and extract .onion addresses from the page."""
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
                return await self.discover_from_text(resp.text)
        except Exception as e:
            logger.warning(f"URL discovery failed for {url}: {e}")
            return []

    async def discover_from_known_dirs(self) -> list[str]:
        """Discover .onion services from known directory sites."""
        dirs = [
            "https://ahmia.fi/onions/",
            "https://darksearch.io/",
        ]
        all_onions: list[str] = []
        for dir_url in dirs:
            onions = await self.discover_from_url(dir_url)
            all_onions.extend(onions)
            await asyncio.sleep(0.5)
        return list(set(all_onions))

    async def classify_onion(self, onion_url: str) -> dict[str, Any]:
        """Fetch and classify an .onion service."""
        result: dict[str, Any] = {
            "url": onion_url,
            "address": onion_url.replace("http://", "").replace("https://", "").rstrip("/"),
            "classified": False,
            "service_type": "unknown",
            "online": False,
        }

        # Fetch the page through Tor
        fetch_result = await tor_controller.fetch_onion(onion_url)

        if "error" in fetch_result:
            result["error"] = fetch_result["error"]
            return result

        result["online"] = True
        result["status"] = fetch_result.get("status", 0)
        result["title"] = fetch_result.get("title", "")
        result["body_size"] = fetch_result.get("body_size", 0)
        result["links"] = fetch_result.get("links", [])[:20]
        result["pgp_keys"] = fetch_result.get("pgp_keys", [])

        # Classify based on title and content
        content = (result["title"] + " " + fetch_result.get("body_preview", "")).lower()

        best_type = "unknown"
        best_score = 0
        for service_type, keywords in SERVICE_TYPES.items():
            score = sum(1 for kw in keywords if kw in content)
            if score > best_score:
                best_score = score
                best_type = service_type

        if best_score > 0:
            result["service_type"] = best_type
            result["classified"] = True
            result["classification_confidence"] = min(1.0, best_score / 3)

        # Detect language (simple heuristic)
        result["language"] = self._detect_language(fetch_result.get("body_preview", ""))

        return result

    def _detect_language(self, text: str) -> str:
        """Simple language detection based on common words."""
        text_lower = text.lower()
        lang_markers = {
            "en": ["the ", "and ", "for ", "with ", "that ", "this "],
            "ru": [" что ", " это ", " для ", " или ", " на "],
            "de": [" und ", " der ", " die ", " das ", " mit "],
            "fr": [" les ", " des ", " que ", " pour ", " dans "],
            "es": [" que ", " para ", " con ", " los ", " una "],
            "zh": ["的", "是", "在", "和"],
        }
        best_lang = "en"
        best_count = 0
        for lang, markers in lang_markers.items():
            count = sum(text_lower.count(m) for m in markers)
            if count > best_count:
                best_count = count
                best_lang = lang
        return best_lang

    async def batch_classify(self, onion_urls: list[str]) -> list[dict[str, Any]]:
        """Classify multiple .onion services."""
        results = []
        for url in onion_urls:
            result = await self.classify_onion(url)
            results.append(result)
            await asyncio.sleep(2.0)  # rate limit for .onion
        return results


onion_collector = OnionCollector()