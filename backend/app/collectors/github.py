"""GitHub recon collector — org repos, leaked secrets, infrastructure mentions.

Uses GitHub's free REST API (60 req/hour unauthenticated, 5000 with token).

Academic basis:
- PIUS (Praetorian, 2025): organizational asset discovery
- Recon-Act (arXiv:2509.21072): self-evolving multi-agent reconnaissance
- OSINT Framework (IEEE 2025): agentic AI in OSINT workflows
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class GitHubCollector:
    """GitHub reconnaissance collector."""

    def __init__(self):
        self.base_url = "https://api.github.com"
        self.token = os.environ.get("ABYSS_GITHUB_TOKEN", "")
        self.client = httpx.AsyncClient(timeout=30.0)

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            h["Authorization"] = f"token {self.token}"
        return h

    async def search_code(self, query: str, per_page: int = 30) -> dict[str, Any]:
        """Search GitHub code for leaked secrets, config files, infrastructure mentions."""
        try:
            resp = await self.client.get(
                f"{self.base_url}/search/code",
                params={"q": query, "per_page": str(per_page)},
                headers=self._headers(),
            )
            if resp.status_code == 429:
                return {"error": "rate_limited"}
            if resp.status_code == 403:
                return {"error": "forbidden", "message": resp.json().get("message", "Rate limit or auth required")}
            resp.raise_for_status()
            data = resp.json()

            results = []
            for item in data.get("items", []):
                results.append({
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "repo_url": item.get("repository", {}).get("html_url", ""),
                    "file": item.get("name", ""),
                    "path": item.get("path", ""),
                    "html_url": item.get("html_url", ""),
                    "score": item.get("score", 0),
                })

            return {
                "query": query,
                "total": data.get("total_count", 0),
                "results": results,
                "count": len(results),
            }
        except Exception as e:
            logger.error(f"GitHub code search failed: {e}")
            return {"error": str(e), "results": [], "count": 0}

    async def search_repos(self, query: str, per_page: int = 30) -> dict[str, Any]:
        """Search GitHub repositories."""
        try:
            resp = await self.client.get(
                f"{self.base_url}/search/repositories",
                params={"q": query, "per_page": str(per_page), "sort": "updated"},
                headers=self._headers(),
            )
            if resp.status_code == 429:
                return {"error": "rate_limited"}
            resp.raise_for_status()
            data = resp.json()

            results = []
            for item in data.get("items", []):
                results.append({
                    "name": item.get("full_name", ""),
                    "url": item.get("html_url", ""),
                    "description": item.get("description", ""),
                    "stars": item.get("stargazers_count", 0),
                    "forks": item.get("forks_count", 0),
                    "language": item.get("language", ""),
                    "created": item.get("created_at", ""),
                    "updated": item.get("updated_at", ""),
                    "topics": item.get("topics", []),
                    "license": item.get("license", {}).get("name", "") if item.get("license") else "",
                })

            return {
                "query": query,
                "total": data.get("total_count", 0),
                "results": results,
                "count": len(results),
            }
        except Exception as e:
            logger.error(f"GitHub repo search failed: {e}")
            return {"error": str(e), "results": [], "count": 0}

    async def search_secrets(self, domain: str) -> dict[str, Any]:
        """Search for leaked secrets related to a domain."""
        secret_patterns = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" AWS_ACCESS_KEY',
            f'"{domain}" PRIVATE KEY',
        ]

        all_results = []
        for query in secret_patterns:
            result = await self.search_code(query, per_page=5)
            if "error" not in result:
                all_results.extend(result.get("results", []))
            await asyncio.sleep(0.5)  # be nice to API

        # Deduplicate by html_url
        seen = set()
        unique = []
        for r in all_results:
            url = r.get("html_url", "")
            if url not in seen:
                seen.add(url)
                unique.append(r)

        return {
            "domain": domain,
            "potential_secrets": unique,
            "count": len(unique),
        }

    async def search_infrastructure(self, domain: str) -> dict[str, Any]:
        """Search GitHub for infrastructure mentions (config files, deploy scripts)."""
        queries = [
            f'"{domain}" filename:.env',
            f'"{domain}" filename:docker-compose.yml',
            f'"{domain}" filename:config.yml',
            f'"{domain}" filename:nginx.conf',
            f'"{domain}" filename:Makefile',
        ]

        all_results = []
        for query in queries:
            result = await self.search_code(query, per_page=5)
            if "error" not in result:
                all_results.extend(result.get("results", []))
            await asyncio.sleep(0.5)

        seen = set()
        unique = []
        for r in all_results:
            url = r.get("html_url", "")
            if url not in seen:
                seen.add(url)
                unique.append(r)

        return {
            "domain": domain,
            "infrastructure_refs": unique,
            "count": len(unique),
        }

    async def get_org_repos(self, org: str) -> dict[str, Any]:
        """Get all public repos for a GitHub organization."""
        try:
            resp = await self.client.get(
                f"{self.base_url}/orgs/{org}/repos",
                params={"per_page": "100", "type": "public"},
                headers=self._headers(),
            )
            if resp.status_code == 404:
                return {"org": org, "error": "Organization not found"}
            resp.raise_for_status()
            data = resp.json()

            repos = []
            for item in data:
                repos.append({
                    "name": item.get("name", ""),
                    "full_name": item.get("full_name", ""),
                    "url": item.get("html_url", ""),
                    "description": item.get("description", ""),
                    "language": item.get("language", ""),
                    "stars": item.get("stargazers_count", 0),
                    "forks": item.get("forks_count", 0),
                    "created": item.get("created_at", ""),
                    "updated": item.get("updated_at", ""),
                    "topics": item.get("topics", []),
                    "size": item.get("size", 0),
                })

            return {"org": org, "repos": repos, "count": len(repos)}
        except Exception as e:
            return {"org": org, "error": str(e), "repos": [], "count": 0}


github_collector = GitHubCollector()