"""WHOIS collector — domain registration timeline, registrar changes, related domains.

Uses python-whois library (free, queries WHOIS servers directly).

Academic basis:
- ShadowMap (2026): passive attack surface mapper
- TORONS (IEEE 2026): network cartography and infrastructure genealogy
- Spoor (2026): autonomous DFIR with timeline reconstruction
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

import whois as python_whois

logger = logging.getLogger(__name__)


class WHOISCollector:
    """WHOIS data collector for domain registration intelligence."""

    def __init__(self):
        self.timeout = 15

    async def lookup(self, domain: str) -> dict[str, Any]:
        """Perform a WHOIS lookup for a domain."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, python_whois.whois, domain)

            if not result or not result.domain_name:
                return {"domain": domain, "found": False}

            # Normalize dates
            def parse_date(d) -> str:
                if isinstance(d, list):
                    d = d[0] if d else ""
                if isinstance(d, datetime):
                    return d.isoformat()
                return str(d) if d else ""

            return {
                "domain": domain,
                "found": True,
                "registrar": result.registrar or "",
                "creation_date": parse_date(result.creation_date),
                "expiration_date": parse_date(result.expiration_date),
                "updated_date": parse_date(result.updated_date),
                "name_servers": list(result.name_servers) if result.name_servers else [],
                "status": list(result.status) if result.status else [],
                "emails": list(result.emails) if result.emails else [],
                "org": result.org or "",
                "country": result.country or "",
                "state": result.state or "",
                "city": result.city or "",
                "address": result.address or "",
                "registrant_name": result.name or "",
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return {"domain": domain, "error": str(e), "found": False}

    async def get_registration_timeline(self, domain: str) -> dict[str, Any]:
        """Get a registration timeline for a domain."""
        whois_data = await self.lookup(domain)
        if not whois_data.get("found"):
            return whois_data

        timeline = []

        if whois_data.get("creation_date"):
            timeline.append({
                "date": whois_data["creation_date"],
                "event": "Domain registered",
                "details": f"Registrar: {whois_data.get('registrar', 'unknown')}",
            })

        if whois_data.get("updated_date"):
            timeline.append({
                "date": whois_data["updated_date"],
                "event": "Domain updated",
                "details": f"Registrar: {whois_data.get('registrar', 'unknown')}",
            })

        if whois_data.get("expiration_date"):
            timeline.append({
                "date": whois_data["expiration_date"],
                "event": "Domain expires",
                "details": f"Registrar: {whois_data.get('registrar', 'unknown')}",
            })

        timeline.sort(key=lambda x: x.get("date", ""))

        return {
            "domain": domain,
            "timeline": timeline,
            "whois": whois_data,
        }

    async def check_related_domains(self, domain: str) -> dict[str, Any]:
        """Check for related domains using registrant email and org."""
        whois_data = await self.lookup(domain)
        if not whois_data.get("found"):
            return {"domain": domain, "related": [], "count": 0}

        # Extract registrant info for correlation
        emails = whois_data.get("emails", [])
        org = whois_data.get("org", "")
        registrant = whois_data.get("registrant_name", "")

        # Note: Finding related domains would require reverse WHOIS lookups
        # which typically need paid services. We return the correlation data
        # for use in the infrastructure genealogy module.
        return {
            "domain": domain,
            "correlation_data": {
                "emails": emails,
                "org": org,
                "registrant": registrant,
                "registrar": whois_data.get("registrar", ""),
            },
            "whois": whois_data,
        }


whois_collector = WHOISCollector()