"""I2P eepsite exploration — Invisible Internet Project.

I2P is a peer-to-peer anonymous network with a different architecture
than Tor. Eepsites are I2P's equivalent of .onion services.

Academic basis:
- Fifty Shades of Darknet (arXiv:2605.19437): I2P network characterization
- TORONS (IEEE 2026): multi-network cartography
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# I2P default ports
I2P_HTTP_PROXY = 4444
I2P_ROUTER_CONSOLE = 7657

# .i2p address regex
I2P_REGEX = re.compile(r"[a-z0-9-]{5,}\.i2p", re.IGNORECASE)


class I2PCollector:
    """Explores I2P eepsites through the I2P HTTP proxy."""

    def __init__(self):
        self.proxy_port = I2P_HTTP_PROXY
        self.console_port = I2P_ROUTER_CONSOLE

    def is_running(self) -> bool:
        """Check if I2P router is running by testing the console port."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", self.console_port))
            s.close()
            return True
        except (socket.error, ConnectionRefusedError):
            return False

    def get_router_info(self) -> dict[str, Any]:
        """Get I2P router status from the router console."""
        if not self.is_running():
            return {"running": False, "error": "I2P router not running"}

        try:
            # Try to fetch router console
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(f"http://127.0.0.1:{self.console_port}/")
                return {
                    "running": True,
                    "console_port": self.console_port,
                    "http_proxy_port": self.proxy_port,
                    "console_status": resp.status_code,
                }
        except Exception as e:
            return {"running": True, "error": str(e)}

    async def fetch_eepsite(self, url: str) -> dict[str, Any]:
        """Fetch an I2P eepsite through the I2P HTTP proxy."""
        if not self.is_running():
            return {"error": "I2P router not running", "url": url}

        try:
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{self.proxy_port}",
                timeout=120.0,  # I2P is slow
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)
                return {
                    "url": str(resp.url),
                    "status": resp.status_code,
                    "title": self._extract_title(resp.text),
                    "body_size": len(resp.text),
                    "body_preview": resp.text[:2000],
                    "links": self._extract_links(str(resp.url), resp.text),
                }
        except httpx.TimeoutException:
            return {"error": "timeout (I2P can be very slow)", "url": url}
        except Exception as e:
            return {"error": str(e), "url": url}

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        from urllib.parse import urljoin
        links = set()
        for match in re.finditer(r'href=["\']?([^"\'>\s]+)', html, re.IGNORECASE):
            href = match.group(1)
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            full_url = urljoin(base_url, href)
            links.add(full_url)
        return list(links)

    async def discover_eepsites(self, text: str) -> list[str]:
        """Extract .i2p addresses from text."""
        found = I2P_REGEX.findall(text)
        return list(set(found))

    async def discover_from_dirs(self) -> list[str]:
        """Discover I2P eepsites from known directories."""
        # Known I2P directories (accessible through proxy)
        dirs = [
            "http://reg.i2p/",
            "http://stats.i2p/",
        ]
        all_eepsites: list[str] = []
        for dir_url in dirs:
            result = await self.fetch_eepsite(dir_url)
            if "error" not in result:
                eepsites = await self.discover_eepsites(result.get("body_preview", ""))
                all_eepsites.extend(eepsites)
        return list(set(all_eepsites))

    def get_status(self) -> dict[str, Any]:
        """Get I2P integration status."""
        return {
            "running": self.is_running(),
            "http_proxy": f"127.0.0.1:{self.proxy_port}",
            "router_console": f"127.0.0.1:{self.console_port}",
            "info": self.get_router_info() if self.is_running() else None,
        }


i2p_collector = I2PCollector()