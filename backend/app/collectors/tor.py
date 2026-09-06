"""Tor integration — Stem controller for circuit management and .onion access.

Uses Stem library to control Tor process, manage circuits, and
route traffic through the Tor SOCKS proxy for .onion exploration.

Academic basis:
- Mimir Crawler (IEEE TIFS 2025): longitudinal Tor hidden service exploration
- ONIONTRACEX (2026): dark web intelligence framework
- TORONS (IEEE 2026): network cartography of anonymous networks
"""

from __future__ import annotations

import asyncio
import logging
import socket
import socks
from typing import Any

import httpx
from stem import Signal
from stem.control import Controller

from app.config import settings

logger = logging.getLogger(__name__)


class TorController:
    """Manages Tor process and SOCKS proxy for anonymous exploration."""

    def __init__(self):
        self.socks_port = settings.tor_socks_port
        self.control_port = settings.tor_control_port
        self.controller: Controller | None = None
        self._tor_client: httpx.AsyncClient | None = None

    def connect(self) -> bool:
        """Connect to Tor control port."""
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            logger.info(f"Connected to Tor control port {self.control_port}")
            return True
        except Exception as e:
            logger.warning(f"Failed to connect to Tor control port: {e}")
            return False

    def is_running(self) -> bool:
        """Check if Tor SOCKS proxy is listening."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", self.socks_port))
            s.close()
            return True
        except (socket.error, ConnectionRefusedError):
            return False

    def new_circuit(self) -> bool:
        """Request a new Tor circuit (new identity)."""
        if not self.controller:
            if not self.connect():
                return False
        try:
            self.controller.signal(Signal.NEWNYM)
            logger.info("Requested new Tor circuit (NEWNYM)")
            return True
        except Exception as e:
            logger.error(f"Failed to get new circuit: {e}")
            return False

    def get_info(self) -> dict[str, Any]:
        """Get Tor status information."""
        info: dict[str, Any] = {
            "socks_port": self.socks_port,
            "control_port": self.control_port,
            "running": self.is_running(),
        }

        if not self.controller:
            self.connect()

        if self.controller:
            try:
                version = self.controller.get_version()
                info["version"] = str(version) if version else "unknown"
                info["address"] = self.controller.get_info("address", "unknown")
                info["fingerprint"] = self.controller.get_info("fingerprint", "unknown")
                circuit_count = len(self.controller.get_circuits())

                # If no circuits exist, trigger a warmup connection through Tor
                # Tor only builds circuits on demand when traffic flows
                if circuit_count == 0 and info["running"]:
                    try:
                        import threading
                        def _warmup():
                            try:
                                s = socks.socksocket()
                                s.set_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
                                s.settimeout(15)
                                s.connect(("check.torproject.org", 80))
                                s.send(b"GET / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n")
                                s.recv(1024)
                                s.close()
                                logger.info("Tor warmup circuit built")
                            except Exception as e:
                                logger.debug(f"Tor warmup failed (non-critical): {e}")
                        t = threading.Thread(target=_warmup, daemon=True)
                        t.start()
                        t.join(timeout=5)
                        # Re-check circuits after warmup
                        circuit_count = len(self.controller.get_circuits())
                    except Exception:
                        pass

                info["circuit_status"] = circuit_count
                flags_str = self.controller.get_info("flags", "")
                info["flags"] = flags_str.split() if flags_str else []
            except Exception as e:
                info["error"] = str(e)

        return info

    def get_tor_client(self) -> httpx.AsyncClient:
        """Get an httpx client configured to route through Tor SOCKS proxy."""
        if self._tor_client is None:
            self._tor_client = httpx.AsyncClient(
                proxy=f"socks5://127.0.0.1:{self.socks_port}",
                timeout=60.0,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (PITBULL/0.3 Tor Explorer)"},
            )
        return self._tor_client

    async def fetch_onion(self, onion_url: str) -> dict[str, Any]:
        """Fetch a .onion URL through the Tor SOCKS proxy."""
        if not self.is_running():
            return {"error": "Tor not running", "url": onion_url}

        client = self.get_tor_client()
        try:
            resp = await client.get(onion_url)
            return {
                "url": str(resp.url),
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "title": self._extract_title(resp.text),
                "body_size": len(resp.text),
                "body_preview": resp.text[:2000],
                "links": self._extract_links(str(resp.url), resp.text),
                "pgp_keys": self._extract_pgp_keys(resp.text),
            }
        except httpx.TimeoutException:
            return {"error": "timeout", "url": onion_url}
        except Exception as e:
            return {"error": str(e), "url": onion_url}

    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        import re
        from urllib.parse import urljoin
        links = set()
        for match in re.finditer(r'href=["\']?([^"\'>\s]+)', html, re.IGNORECASE):
            href = match.group(1)
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            full_url = urljoin(base_url, href)
            links.add(full_url)
        return list(links)

    def _extract_pgp_keys(self, html: str) -> list[str]:
        """Extract PGP public key blocks from HTML."""
        import re
        keys = []
        for match in re.finditer(
            r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
            html, re.DOTALL,
        ):
            keys.append(match.group(0))
        return keys

    async def crawl_onion(self, onion_url: str, max_pages: int = 10) -> dict[str, Any]:
        """Crawl a .onion site through Tor."""
        if not self.is_running():
            return {"error": "Tor not running"}

        visited: set[str] = set()
        pages: list[dict[str, Any]] = []

        await self._crawl_onion_recursive(onion_url, 2, visited, pages, max_pages)

        return {
            "start_url": onion_url,
            "pages_crawled": len(pages),
            "pages": pages,
        }

    async def _crawl_onion_recursive(
        self,
        url: str,
        depth: int,
        visited: set[str],
        pages: list[dict[str, Any]],
        max_pages: int,
    ) -> None:
        if depth <= 0 or url in visited or len(pages) >= max_pages:
            return

        visited.add(url)
        result = await self.fetch_onion(url)

        if "error" not in result:
            pages.append(result)
            if depth > 1:
                for link in result.get("links", [])[:10]:  # limit links
                    if ".onion" in link and link not in visited:
                        await asyncio.sleep(1.0)  # rate limit for .onion
                        await self._crawl_onion_recursive(link, depth - 1, visited, pages, max_pages)

    def close(self) -> None:
        """Close Tor controller connection."""
        if self.controller:
            self.controller.close()
            self.controller = None
        if self._tor_client:
            # Close async client
            pass


tor_controller = TorController()