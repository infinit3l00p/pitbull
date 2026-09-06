"""Wayback Machine collector — historical snapshots, deleted content, URL changes.

Uses the Wayback Machine CDX API (free, no key required).

Academic basis:
- ShadowMap (2026): passive attack surface mapper using historical data
- Mimir Crawler (IEEE TIFS 2025): longitudinal tracking of services over time
- Spoor (2026): autonomous DFIR with timeline reconstruction
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class WaybackCollector:
    """Wayback Machine CDX API collector for historical web data."""

    def __init__(self):
        self.cdx_url = "https://web.archive.org/cdx/search/cdx"
        self.availability_url = "https://archive.org/wayback/available"
        self.client = httpx.AsyncClient(timeout=60.0)

    async def get_snapshots(self, domain: str, limit: int = 100) -> dict[str, Any]:
        """Get historical snapshots for a domain from the Wayback Machine CDX API."""
        try:
            resp = await self.client.get(
                self.cdx_url,
                params={
                    "url": f"{domain}/*",
                    "output": "json",
                    "collapse": "urlkey",
                    "limit": str(limit),
                    "fl": "timestamp,original,statuscode,mimetype,digest",
                },
            )
            resp.raise_for_status()
            data = resp.json()

            if not data or len(data) < 2:
                return {"domain": domain, "snapshots": [], "count": 0}

            # First row is headers
            headers = data[0]
            snapshots = []
            for row in data[1:]:
                entry = dict(zip(headers, row))
                # Parse timestamp
                ts = entry.get("timestamp", "")
                if len(ts) >= 14:
                    try:
                        dt = datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
                        entry["datetime"] = dt.isoformat()
                    except ValueError:
                        pass
                snapshots.append(entry)

            return {
                "domain": domain,
                "snapshots": snapshots,
                "count": len(snapshots),
                "first_snapshot": snapshots[0] if snapshots else None,
                "last_snapshot": snapshots[-1] if snapshots else None,
            }
        except Exception as e:
            logger.error(f"Wayback CDX query failed for {domain}: {e}")
            return {"domain": domain, "error": str(e), "snapshots": [], "count": 0}

    async def get_url_history(self, url: str, limit: int = 50) -> dict[str, Any]:
        """Get snapshot history for a specific URL."""
        try:
            resp = await self.client.get(
                self.cdx_url,
                params={
                    "url": url,
                    "output": "json",
                    "limit": str(limit),
                    "fl": "timestamp,statuscode,mimetype,digest",
                },
            )
            resp.raise_for_status()
            data = resp.json()

            if not data or len(data) < 2:
                return {"url": url, "history": [], "count": 0}

            headers = data[0]
            history = []
            for row in data[1:]:
                entry = dict(zip(headers, row))
                ts = entry.get("timestamp", "")
                if len(ts) >= 14:
                    try:
                        dt = datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
                        entry["datetime"] = dt.isoformat()
                    except ValueError:
                        pass
                history.append(entry)

            return {"url": url, "history": history, "count": len(history)}
        except Exception as e:
            return {"url": url, "error": str(e), "history": [], "count": 0}

    async def find_deleted_pages(self, domain: str, limit: int = 200) -> dict[str, Any]:
        """Find pages that existed historically but may be deleted now (404 in recent snapshots)."""
        snapshots = await self.get_snapshots(domain, limit=limit)
        if "error" in snapshots:
            return snapshots

        deleted = []
        all_snapshots = snapshots.get("snapshots", [])

        # Group by URL
        urls: dict[str, list] = {}
        for snap in all_snapshots:
            original = snap.get("original", "")
            if original:
                urls.setdefault(original, []).append(snap)

        # Find URLs where later snapshots returned 404
        for url, snaps in urls.items():
            snaps.sort(key=lambda s: s.get("timestamp", ""))
            if snaps:
                last = snaps[-1]
                if last.get("statuscode") == "404":
                    deleted.append({
                        "url": url,
                        "first_seen": snaps[0].get("datetime", ""),
                        "last_seen": last.get("datetime", ""),
                        "last_status": last.get("statuscode"),
                        "snapshot_count": len(snaps),
                    })

        return {
            "domain": domain,
            "deleted_pages": deleted,
            "count": len(deleted),
        }

    async def find_status_code_changes(self, domain: str, limit: int = 200) -> dict[str, Any]:
        """Find URLs where the status code changed over time (e.g., 200 → 403)."""
        snapshots = await self.get_snapshots(domain, limit=limit)
        if "error" in snapshots:
            return snapshots

        changes = []
        all_snapshots = snapshots.get("snapshots", [])

        urls: dict[str, list] = {}
        for snap in all_snapshots:
            original = snap.get("original", "")
            if original:
                urls.setdefault(original, []).append(snap)

        for url, snaps in urls.items():
            if len(snaps) < 2:
                continue
            snaps.sort(key=lambda s: s.get("timestamp", ""))
            status_codes = set(s.get("statuscode", "") for s in snaps if s.get("statuscode"))
            if len(status_codes) > 1:
                changes.append({
                    "url": url,
                    "status_codes": list(status_codes),
                    "first": snaps[0].get("datetime", ""),
                    "last": snaps[-1].get("datetime", ""),
                    "snapshots": len(snaps),
                })

        return {"domain": domain, "status_changes": changes, "count": len(changes)}


wayback_collector = WaybackCollector()