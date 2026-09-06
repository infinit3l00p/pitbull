"""DNS reconnaissance collector — subdomain discovery and DNS enumeration.

Academic basis:
- SubreconGemini (2025): hybrid AI + wordlist + CT log subdomain discovery
- ShadowMap (2026): passive attack surface mapper using CT + DNS + AI
- PIUS (Praetorian, 2025): organizational asset discovery with 20+ plugins
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import dns.resolver
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Common subdomain wordlist for brute-force
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "MX", "mx", "admin", "portal", "api", "dev", "test",
    "staging", "beta", "demo", "shop", "blog", "forum", "wiki", "docs", "app",
    "m", "mobile", "secure", "vpn", "remote", "gateway", "proxy", "cdp",
    "dashboard", "panel", "console", "manage", "management", "internal",
    "intranet", "extranet", "git", "svn", "jenkins", "ci", "build", "deploy",
    "monitor", "status", "health", "grafana", "prometheus", "kibana",
    "elastic", "log", "logs", "sentry", "analytics", "track", "stats",
    "backup", "backups", "old", "new", "v2", "v1", "s3", "storage",
    "db", "database", "redis", "memcached", "rabbitmq", "kafka",
    "auth", "sso", "oauth", "login", "register", "account", "user",
    "cdn", "static", "assets", "media", "images", "img", "css", "js",
    "search", "api1", "api2", "rest", "graphql", "gql", "rpc", "json",
    "ws", "wss", "websocket", "stream", "realtime", "chat", "message",
    "support", "help", "faq", "info", "about", "contact", "legal",
    "secure", "ssl", "tls", "cert", "crl", "ocsp", "pki",
    "nginx", "apache", "tomcat", "node", "python", "php", "ruby",
    "docker", "k8s", "kubernetes", "registry", "harbor",
]


class DNSCollector:
    """DNS reconnaissance and subdomain discovery."""

    def __init__(self):
        self.timeout = settings.crawler_timeout_s

    async def resolve(self, hostname: str, record_type: str = "A") -> list[str]:
        """Resolve DNS records for a hostname."""
        try:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
            )
            return list({r[4][0] for r in results})
        except socket.gaierror:
            return []

    async def enumerate_subdomains(self, domain: str) -> list[dict[str, Any]]:
        """Discover subdomains using multiple methods."""
        subdomains: dict[str, str] = {}  # name -> ip

        # Method 1: Certificate Transparency (crt.sh)
        ct_subs = await self._crt_sh(domain)
        for sub in ct_subs:
            if sub not in subdomains:
                subdomains[sub] = ""
        logger.info(f"crt.sh found {len(ct_subs)} subdomains for {domain}")

        # Method 2: DNS brute force with wordlist
        brute_subs = await self._dns_brute(domain)
        for sub in brute_subs:
            if sub not in subdomains:
                subdomains[sub] = ""
        logger.info(f"DNS brute found {len(brute_subs)} subdomains for {domain}")

        # Method 3: Resolve all found subdomains
        results = []
        for subname in subdomains:
            ips = await self.resolve(subname)
            results.append({
                "subdomain": subname,
                "ips": ips,
                "source": "crt.sh+brute" if subname in ct_subs and subname in brute_subs else "crt.sh" if subname in ct_subs else "brute",
            })

        return results

    async def _crt_sh(self, domain: str) -> list[str]:
        """Query crt.sh for certificate transparency subdomains."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if resp.status_code != 200:
                    return []
                data = resp.json()
                subs = set()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and domain in name and name != domain:
                            subs.add(name)
                return list(subs)
        except Exception as e:
            logger.warning(f"crt.sh query failed for {domain}: {e}")
            return []

    async def _dns_brute(self, domain: str, max_concurrent: int = 50) -> list[str]:
        """DNS brute force using wordlist."""
        semaphore = asyncio.Semaphore(max_concurrent)
        found = []

        async def check(sub: str):
            async with semaphore:
                hostname = f"{sub}.{domain}"
                ips = await self.resolve(hostname)
                if ips:
                    found.append(hostname)

        tasks = [check(sub) for sub in SUBDOMAIN_WORDLIST]
        await asyncio.gather(*tasks)
        return found

    async def get_dns_records(self, domain: str) -> dict[str, list[str]]:
        """Get common DNS records for a domain using dnspython."""
        records: dict[str, list[str]] = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0

        for rt in record_types:
            try:
                loop = asyncio.get_event_loop()

                def _resolve(rt=rt):
                    try:
                        answers = resolver.resolve(domain, rt)
                        return [str(r) for r in answers]
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                            dns.resolver.NoNameservers, dns.exception.Timeout):
                        return []
                    except Exception:
                        return []

                records[rt] = await loop.run_in_executor(None, _resolve)
            except Exception:
                records[rt] = []

        return records


dns_collector = DNSCollector()