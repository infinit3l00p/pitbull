"""Certificate Transparency collector — subdomain discovery via CT logs.

Academic basis:
- ShadowMap (2026): passive attack surface mapper using certificate transparency
- PIUS (Praetorian, 2025): organizational asset discovery using CT logs
- SubreconGemini (2025): hybrid subdomain discovery combining CT + AI
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class CertificateCollector:
    """Certificate Transparency log collector."""

    def __init__(self):
        self.timeout = 30

    async def get_certificates(self, domain: str) -> list[dict[str, Any]]:
        """Query crt.sh for certificates related to a domain."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"https://crt.sh/?q={domain}&output=json")
                if resp.status_code != 200:
                    logger.warning(f"crt.sh returned {resp.status_code} for {domain}")
                    return []

                data = resp.json()
                certs = []

                for entry in data:
                    cert = {
                        "issuer_ca_id": entry.get("issuer_ca_id", ""),
                        "issuer_name": entry.get("issuer_name", ""),
                        "common_name": entry.get("common_name", ""),
                        "name_value": entry.get("name_value", ""),
                        "id": entry.get("id", ""),
                        "entry_timestamp": entry.get("entry_timestamp", ""),
                        "not_before": entry.get("not_before", ""),
                        "not_after": entry.get("not_after", ""),
                        "serial_number": entry.get("serial_number", ""),
                    }

                    # Parse all domains from name_value (can be multiline)
                    domains = [d.strip().lstrip("*.") for d in cert["name_value"].split("\n") if d.strip()]
                    cert["all_domains"] = domains
                    certs.append(cert)

                logger.info(f"Found {len(certs)} certificates for {domain}")
                return certs

        except Exception as e:
            logger.error(f"Certificate collection failed for {domain}: {e}")
            return []

    async def extract_subdomains(self, domain: str) -> list[str]:
        """Extract all unique subdomains from CT logs."""
        certs = await self.get_certificates(domain)
        subs = set()

        for cert in certs:
            for d in cert.get("all_domains", []):
                if d and domain in d and d != domain:
                    subs.add(d)

        return list(subs)

    async def detect_wildcard(self, domain: str) -> bool:
        """Check if domain has a wildcard certificate."""
        certs = await self.get_certificates(domain)
        for cert in certs:
            if cert.get("name_value", "").startswith("*."):
                return True
        return False


certificate_collector = CertificateCollector()