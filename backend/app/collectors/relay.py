"""Tor relay census — maps the Tor network infrastructure.

Tracks relays, their flags, bandwidth, and geographic distribution.
Builds a cartographic map of the Tor network.

Academic basis:
- TORONS (IEEE 2026): network cartography of anonymous networks
- Mimir Crawler (IEEE TIFS 2025): HSDir census for service discovery
- Fifty Shades of Darknet (arXiv:2605.19437): multi-network characterization
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class RelayCensus:
    """Collects and maps Tor relay infrastructure."""

    def __init__(self):
        self.collector_url = "https://collector.torproject.org"
        self.onionoo_url = "https://onionoo.torproject.org/details"

    async def get_relays(self, limit: int = 100, search: str = "") -> dict[str, Any]:
        """Get Tor relay data from Onionoo API."""
        params: dict[str, str] = {
            "type": "relay",
            "running": "true",
            "limit": str(limit),
        }
        if search:
            params["search"] = search

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(self.onionoo_url, params=params)
                if resp.status_code != 200:
                    return {"error": f"Onionoo returned {resp.status_code}"}
                data = resp.json()

                relays = []
                for r in data.get("relays", []):
                    relays.append({
                        "nickname": r.get("nickname", ""),
                        "fingerprint": r.get("fingerprint", ""),
                        "flags": r.get("flags", []),
                        "country": r.get("country", ""),
                        "country_name": r.get("country_name", ""),
                        "bandwidth_burst": r.get("bandwidth_burst", 0),
                        "bandwidth_average": r.get("bandwidth_average", 0),
                        "bandwidth_observed": r.get("bandwidth_observed", 0),
                        "advertised_bandwidth": r.get("advertised_bandwidth", 0),
                        "or_addresses": r.get("or_addresses", []),
                        "exit_addresses": r.get("exit_addresses", []),
                        "dir_address": r.get("dir_address", ""),
                        "first_seen": r.get("first_seen", ""),
                        "last_seen": r.get("last_seen", ""),
                        "running": r.get("running", False),
                        "contact": r.get("contact", ""),
                        "platform": r.get("platform", ""),
                        "version": r.get("version", ""),
                        "as_number": r.get("as_number", ""),
                        "as_name": r.get("as_name", ""),
                        "effective_family": r.get("effective_family", []),
                    })

                return {
                    "total_relays": data.get("relays_truncated", len(relays)),
                    "relays": relays,
                    "count": len(relays),
                    "query_time": data.get("query_time", ""),
                }
        except Exception as e:
            logger.error(f"Relay census failed: {e}")
            return {"error": str(e), "relays": [], "count": 0}

    async def get_bridge_summary(self) -> dict[str, Any]:
        """Get summary of Tor network status."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get("https://onionoo.torproject.org/summary")
                if resp.status_code != 200:
                    return {"error": f"Onionoo summary returned {resp.status_code}"}
                data = resp.json()
                return {
                    "relays": data.get("relays", []),
                    "bridges": data.get("bridges", []),
                    "query_time": data.get("query_time", ""),
                }
        except Exception as e:
            return {"error": str(e)}

    def analyze_census(self, relays: list[dict[str, Any]]) -> dict[str, Any]:
        """Analyze relay census data for patterns."""
        countries: dict[str, int] = {}
        asns: dict[str, int] = {}
        flags: dict[str, int] = {}
        total_bandwidth = 0

        for relay in relays:
            country = relay.get("country", "unknown")
            countries[country] = countries.get(country, 0) + 1

            asn = relay.get("as_number", "unknown")
            asns[asn] = asns.get(asn, 0) + 1

            for flag in relay.get("flags", []):
                flags[flag] = flags.get(flag, 0) + 1

            total_bandwidth += relay.get("advertised_bandwidth", 0)

        return {
            "total_relays": len(relays),
            "countries": dict(sorted(countries.items(), key=lambda x: x[1], reverse=True)[:20]),
            "top_asns": dict(sorted(asns.items(), key=lambda x: x[1], reverse=True)[:10]),
            "flags_distribution": flags,
            "total_advertised_bandwidth": total_bandwidth,
            "avg_bandwidth": total_bandwidth // len(relays) if relays else 0,
        }


relay_census = RelayCensus()