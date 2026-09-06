"""Shodan collector — exposed devices, services, and ports.

Uses Shodan's free API tier (requires API key).
Free tier: 100 queries/month, 1 result per query, IP lookups.

Academic basis:
- PIUS (Praetorian, 2025): organizational asset discovery with 20+ plugins
- ShadowMap (2026): passive attack surface mapper
- AWE (arXiv:2603.00960): adaptive strategy based on target responses
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class ShodanCollector:
    """Shodan API integration for exposed device discovery."""

    def __init__(self):
        self.api_key = ""  # Set via env PITBULL_SHODAN_API_KEY
        self.base_url = "https://api.shodan.io"
        self.client = httpx.AsyncClient(timeout=30.0)

    def _get_key(self) -> str:
        import os
        return os.environ.get("PITBULL_SHODAN_API_KEY", settings.shodan_api_key or self.api_key)

    async def host_lookup(self, ip: str) -> dict[str, Any]:
        """Get Shodan information for a specific IP."""
        key = self._get_key()
        if not key:
            logger.warning("No Shodan API key set — skipping host lookup")
            return {"error": "no_api_key", "ip": ip}

        try:
            resp = await self.client.get(
                f"{self.base_url}/shodan/host/{ip}",
                params={"key": key},
            )
            if resp.status_code == 404:
                return {"ip": ip, "found": False, "note": "No Shodan data for this IP"}
            if resp.status_code == 429:
                return {"ip": ip, "error": "rate_limited"}
            resp.raise_for_status()
            data = resp.json()

            return {
                "ip": ip,
                "found": True,
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "asn": data.get("asn", ""),
                "os": data.get("os", ""),
                "country": data.get("country_name", ""),
                "city": data.get("city", ""),
                "latitude": data.get("latitude", 0),
                "longitude": data.get("longitude", 0),
                "vulns": data.get("vulns", []),
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport"),
                        "product": s.get("product", ""),
                        "version": s.get("version", ""),
                        "banner": s.get("data", "")[:500],
                        "cpe": s.get("cpe", ""),
                    }
                    for s in data.get("data", [])
                ],
                "tags": data.get("tags", []),
            }
        except Exception as e:
            logger.error(f"Shodan host lookup failed for {ip}: {e}")
            return {"ip": ip, "error": str(e)}

    async def search(self, query: str, page: int = 1) -> dict[str, Any]:
        """Search Shodan for devices matching a query (free tier: 1 result)."""
        key = self._get_key()
        if not key:
            return {"error": "no_api_key"}

        try:
            resp = await self.client.get(
                f"{self.base_url}/shodan/host/search",
                params={"key": key, "query": query, "page": page},
            )
            if resp.status_code == 429:
                return {"error": "rate_limited"}
            resp.raise_for_status()
            data = resp.json()

            return {
                "total": data.get("total", 0),
                "results": [
                    {
                        "ip": r.get("ip_str", ""),
                        "port": r.get("port"),
                        "hostnames": r.get("hostnames", []),
                        "org": r.get("org", ""),
                        "os": r.get("os", ""),
                        "product": r.get("product", ""),
                        "version": r.get("version", ""),
                        "country": r.get("country_name", ""),
                    }
                    for r in data.get("matches", [])
                ],
            }
        except Exception as e:
            logger.error(f"Shodan search failed: {e}")
            return {"error": str(e)}

    async def info(self) -> dict[str, Any]:
        """Get API account info (query credits, plan)."""
        key = self._get_key()
        if not key:
            return {"error": "no_api_key"}

        try:
            resp = await self.client.get(
                f"{self.base_url}/api-info",
                params={"key": key},
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    async def lookup_ips(self, ips: list[str]) -> list[dict[str, Any]]:
        """Look up multiple IPs on Shodan."""
        results = []
        for ip in ips:
            result = await self.host_lookup(ip)
            results.append(result)
            if "error" not in result or result.get("error") != "rate_limited":
                await asyncio.sleep(1.0)  # rate limit
            else:
                break
        return results


shodan_collector = ShodanCollector()