"""Deep web probing collector — login forms, hidden APIs, exposed config endpoints.

Goes beyond surface crawling to detect:
- Login/auth forms and their mechanisms
- Swagger/OpenAPI/GraphQL endpoints
- Exposed admin panels and config interfaces
- Hidden API endpoints (REST, GraphQL, etc.)

Academic basis:
- Web-CogReasoner (arXiv:2508.01858): knowledge-induced cognitive reasoning
- PenForge (arXiv:2601.06910): dynamic expert agent construction
- AWE (arXiv:2603.00960): adaptive strategy based on target responses
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Common paths to probe for deep web content
DEEP_WEB_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/admin/login", "/administrator", "/admin.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/manager", "/manage",
    "/dashboard", "/console", "/panel", "/control", "/cpanel",
    # API docs
    "/api", "/api/", "/api/docs", "/api/swagger", "/api/swagger-ui",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json",
    "/openapi", "/openapi.json", "/openapi.yaml", "/api/openapi.json",
    "/graphql", "/graphql/schema", "/graphiql", "/playground",
    "/api/graphql", "/api/v1", "/api/v2", "/api/v3",
    # Config files
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/config.json", "/config.yml", "/config.yaml", "/config.ini",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/package.json", "/composer.json", "/Gemfile",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    # Debug/dev endpoints
    "/debug", "/debug/pprof", "/_debug", "/__debug__",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
    "/metrics", "/healthz", "/health", "/status",
    "/phpinfo.php", "/info.php", "/test.php",
    # Backup files
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/dump.sql",
    "/.bak", "/index.php.bak", "/config.php.bak",
    # Misc
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/server-status", "/server-info",
    "/.well-known/security.txt", "/security.txt",
]

# Patterns that indicate interesting findings
AUTH_PATTERNS = [
    r'<input[^>]*type=["\']?password["\']?',  # Password fields
    r'<form[^>]*action=["\']?[^"\'>]*login[^"\'>]*["\']?',  # Login forms
    r'<form[^>]*action=["\']?[^"\'>]*auth[^"\'>]*["\']?',  # Auth forms
    r'authorization',  # Auth headers/mentions
    r'oauth', r'jwt', r'bearer', r'token',
]

API_INDICATORS = [
    '"swagger"', '"openapi"', '"graphql"', '"queries"',
    '"mutations"', '"schema"', '"resolvers"',
    '"endpoints"', '"paths"', '"info"',
]


class DeepWebCollector:
    """Deep web probing — finds content behind forms and hidden APIs."""

    def __init__(self):
        self.timeout = settings.crawler_timeout_s
        self.user_agent = settings.crawler_user_agent
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
        )

    async def probe(self, base_url: str, paths: list[str] | None = None) -> dict[str, Any]:
        """Probe a target for deep web content by testing common paths."""
        paths_to_test = paths or DEEP_WEB_PATHS
        results: list[dict[str, Any]] = []

        # Remove duplicate protocol
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        base = base_url.rstrip("/")

        # Probe paths concurrently with rate limiting
        semaphore = asyncio.Semaphore(10)

        async def probe_path(path: str):
            async with semaphore:
                url = f"{base}{path}"
                try:
                    resp = await self.client.get(
                        url,
                        headers={"User-Agent": self.user_agent},
                    )

                    # Only store interesting responses (not 404)
                    if resp.status_code == 404:
                        return

                    finding_type = self._classify_response(path, resp)
                    if not finding_type:
                        return

                    result = {
                        "url": url,
                        "path": path,
                        "status": resp.status_code,
                        "type": finding_type,
                        "content_length": len(resp.text),
                        "content_type": resp.headers.get("content-type", ""),
                        "interesting": self._extract_interesting_content(path, resp.text),
                        "server": resp.headers.get("server", ""),
                    }
                    results.append(result)

                except Exception:
                    pass

        tasks = [probe_path(p) for p in paths_to_test]
        await asyncio.gather(*tasks)

        # Categorize results
        categories: dict[str, list] = {}
        for r in results:
            cat = r["type"]
            categories.setdefault(cat, []).append(r)

        return {
            "base_url": base_url,
            "probed": len(paths_to_test),
            "found": len(results),
            "categories": categories,
            "results": results,
        }

    def _classify_response(self, path: str, resp: httpx.Response) -> str | None:
        """Classify what type of resource was found."""
        status = resp.status_code
        content = resp.text.lower() if resp.text else ""
        content_type = resp.headers.get("content-type", "").lower()

        # API documentation
        if any(p in path for p in ["/swagger", "/openapi", "/api-docs"]):
            if status == 200 and ("swagger" in content or "openapi" in content or "api" in content):
                return "api_documentation"

        # GraphQL
        if "graphql" in path:
            if status == 200 or status == 400:
                return "graphql_endpoint"

        # Admin panels
        if any(p in path for p in ["/admin", "/wp-admin", "/dashboard", "/console", "/panel", "/manage"]):
            if status in (200, 301, 302, 401, 403):
                return "admin_panel"

        # Config files
        if any(p in path for p in ["/.env", "/config.", "/docker-compose", "/Dockerfile"]):
            if status == 200:
                return "exposed_config"

        # Git exposure
        if ".git" in path:
            if status == 200:
                return "exposed_git"

        # Backup files
        if any(p in path for p in ["/backup", ".sql", ".bak", "/dump"]):
            if status == 200:
                return "backup_file"

        # Debug/actuator endpoints
        if any(p in path for p in ["/debug", "/actuator", "/phpinfo", "/server-status"]):
            if status == 200:
                return "debug_endpoint"

        # Login/auth forms
        if status == 200 and any(re.search(p, content, re.IGNORECASE) for p in AUTH_PATTERNS):
            return "auth_form"

        # API base
        if "/api" in path and status in (200, 401, 403):
            return "api_endpoint"

        # Security.txt
        if "security.txt" in path and status == 200:
            return "security_contact"

        # Robots/sitemap
        if path in ("/robots.txt", "/sitemap.xml") and status == 200:
            return "crawler_directive"

        # Anything that returns 200 on unusual paths
        if status == 200 and content_length_check(resp):
            return "exposed_content"

        # 401/403 = exists but protected
        if status in (401, 403):
            return "protected_resource"

        return None

    def _extract_interesting_content(self, path: str, content: str) -> str:
        """Extract interesting snippets from the response."""
        snippets = []

        # For .env files, extract key names (not values for safety)
        if ".env" in path:
            for match in re.finditer(r'^([A-Z_]+)=', content, re.MULTILINE):
                snippets.append(f"ENV var: {match.group(1)}=***")

        # For swagger/openapi, extract API paths
        if "swagger" in path or "openapi" in path:
            for match in re.finditer(r'"(/[^"]+)"', content):
                snippets.append(f"API path: {match.group(1)}")

        # For GraphQL, extract schema info
        if "graphql" in path:
            if "query" in content.lower():
                snippets.append("GraphQL schema detected")

        # For robots.txt, extract disallowed paths
        if path == "/robots.txt":
            for match in re.finditer(r'Disallow:\s*(.+)', content, re.IGNORECASE):
                snippets.append(f"Disallowed: {match.group(1).strip()}")

        return "; ".join(snippets[:10])


def content_length_check(resp: httpx.Response) -> bool:
    """Check if response has meaningful content."""
    return len(resp.text) > 50


deep_web_collector = DeepWebCollector()