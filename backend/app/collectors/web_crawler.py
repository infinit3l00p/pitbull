"""Web crawler collector — Playwright-based browser crawling and page analysis.

Academic basis:
- Web-CogReasoner (arXiv:2508.01858): knowledge-induced cognitive reasoning for web
- Recon-Act (arXiv:2509.21072): self-evolving multi-agent browser system
- Browsing Like Human (ACL 2025): multimodal web agent with fast/slow thinking
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class WebCrawler:
    """Lightweight HTTP-based web crawler for surface web exploration."""

    def __init__(self):
        self.timeout = settings.crawler_timeout_s
        self.max_depth = settings.crawler_max_depth
        self.max_pages = settings.crawler_max_pages
        self.rate_limit_ms = settings.crawler_rate_limit_ms
        self.user_agent = settings.crawler_user_agent

    async def crawl(self, url: str, max_depth: int | None = None) -> dict[str, Any]:
        """Crawl a URL and return page analysis."""
        depth = max_depth or self.max_depth
        visited: set[str] = set()
        pages: list[dict[str, Any]] = []

        await self._crawl_recursive(url, depth, visited, pages)

        return {
            "start_url": url,
            "pages_crawled": len(pages),
            "pages": pages,
        }

    async def _crawl_recursive(
        self,
        url: str,
        depth: int,
        visited: set[str],
        pages: list[dict[str, Any]],
    ) -> None:
        if depth <= 0 or url in visited or len(pages) >= self.max_pages:
            return

        visited.add(url)

        page = await self._fetch_page(url)
        if page:
            pages.append(page)

            # Extract links for deeper crawling
            if depth > 1:
                links = page.get("links", [])
                for link in links[:20]:  # limit links per page
                    await asyncio.sleep(self.rate_limit_ms / 1000.0)
                    await self._crawl_recursive(link, depth - 1, visited, pages)

    async def _fetch_page(self, url: str) -> dict[str, Any] | None:
        """Fetch and analyze a single page."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(
                    url,
                    headers={"User-Agent": self.user_agent},
                )

                page = {
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "title": self._extract_title(resp.text),
                    "links": self._extract_links(str(resp.url), resp.text),
                    "forms": self._extract_forms(resp.text),
                    "tech_hints": self._detect_tech(resp.headers, resp.text),
                    "interesting_paths": self._find_interesting_paths(resp.text),
                    "body_size": len(resp.text),
                }

                logger.info(f"Crawled {url} → {page['status_code']} ({page['body_size']} bytes, {len(page['links'])} links)")
                return page

        except Exception as e:
            logger.warning(f"Failed to crawl {url}: {e}")
            return None

    def _extract_title(self, html: str) -> str:
        """Extract page title."""
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        """Extract all links from a page."""
        import re
        from urllib.parse import urljoin

        links = set()
        for match in re.finditer(r'href=["\']?([^"\'>\s]+)', html, re.IGNORECASE):
            href = match.group(1)
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full_url = urljoin(base_url, href)
            links.add(full_url)

        return list(links)

    def _extract_forms(self, html: str) -> list[dict[str, Any]]:
        """Extract forms from a page."""
        import re

        forms = []
        for match in re.finditer(
            r"<form[^>]*>(.*?)</form>", html, re.IGNORECASE | re.DOTALL
        ):
            form_html = match.group(0)
            action = re.search(r'action=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
            method = re.search(r'method=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)

            inputs = re.findall(
                r'<input[^>]*name=["\']?([^"\'>\s/]+)[^>]*type=["\']?([^"\'>\s/]+)',
                form_html,
                re.IGNORECASE,
            )

            forms.append({
                "action": action.group(1) if action else "",
                "method": method.group(1).upper() if method else "GET",
                "fields": [{"name": n, "type": t} for n, t in inputs],
            })

        return forms

    def _detect_tech(self, headers: dict, html: str) -> list[str]:
        """Detect technology stack from headers and content."""
        tech = []

        # Header-based detection
        server = headers.get("server", "").lower()
        if "nginx" in server:
            tech.append("Nginx")
        if "apache" in server:
            tech.append("Apache")
        if "cloudflare" in server:
            tech.append("Cloudflare")
        if "express" in server:
            tech.append("Express.js")

        powered_by = headers.get("x-powered-by", "").lower()
        if "php" in powered_by:
            tech.append("PHP")
        if "asp.net" in powered_by:
            tech.append("ASP.NET")
        if "express" in powered_by:
            tech.append("Express.js")

        # Content-based detection
        html_lower = html.lower()
        if "wp-content" in html_lower or "wp-includes" in html_lower:
            tech.append("WordPress")
        if "cdn.jsdelivr.net" in html_lower:
            tech.append("jsDelivr CDN")
        if "react" in html_lower and ("__next" in html_lower or "next.js" in html_lower):
            tech.append("Next.js")
        if "vue" in html_lower:
            tech.append("Vue.js")
        if "angular" in html_lower:
            tech.append("Angular")
        if "jquery" in html_lower:
            tech.append("jQuery")
        if "bootstrap" in html_lower:
            tech.append("Bootstrap")
        if "tailwind" in html_lower:
            tech.append("Tailwind CSS")
        if "cloudflare" in html_lower and "cdn-cgi/challenge" in html_lower:
            tech.append("Cloudflare Protection")

        return list(set(tech))

    def _find_interesting_paths(self, html: str) -> list[str]:
        """Find interesting paths mentioned in the page (API endpoints, admin, etc.)."""
        import re

        interesting = []
        patterns = [
            r'["\'](/[a][d][m][i][n][^"\']*)["\']',
            r'["\'](/[a][p][i][^"\']*)["\']',
            r'["\'](/[wp]-[^"\']*)["\']',
            r'["\']/(wp-admin[^"\']*)["\']',
            r'["\']/(wp-json[^"\']*)["\']',
            r'["\']/(graphql[^"\']*)["\']',
            r'["\']/(swagger[^"\']*)["\']',
            r'["\']/(\.env[^"\']*)["\']',
            r'["\']/(\.git[^"\']*)["\']',
            r'["\']/(config[^"\']*)["\']',
            r'["\']/(backup[^"\']*)["\']',
            r'["\']/(debug[^"\']*)["\']',
            r'["\']/(console[^"\']*)["\']',
            r'["\']/(dashboard[^"\']*)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            interesting.extend(matches[:5])  # max 5 per pattern

        return list(set(interesting))


web_crawler = WebCrawler()