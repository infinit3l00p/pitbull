"""Sentinel Auto-Blocker — automatic IP blocking via UFW firewall.

Integrates with UFW to block malicious IPs automatically based on detection severity,
maintains blocklists in memory and Neo4j, and supports whitelisting.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)

# ── Blocking thresholds ───────────────────────────────────────────
# CRITICAL: block immediately (1 detection)
# HIGH:     block after 3 detections
# MEDIUM:   block after 10 detections
# LOW:      log only, no block

BLOCK_THRESHOLDS = {
    "CRITICAL": 0,  # auto-block DISABLED — too many false positives from ntopng
    "HIGH": 0,    # auto-block DISABLED — re-enable when ntopng checks are tuned
    "MEDIUM": 0,  # auto-block DISABLED
    "LOW": 0,     # never auto-block
}

# Default whitelist — localhost, local kernel, and private networks
DEFAULT_WHITELIST = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",  # VIGIL local kernel detections (no remote attacker)
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fe80::/10",  # IPv6 link-local (router neighbor discovery)
    "ff00::/8",  # IPv6 multicast
    "185.183.33.11",  # ProtonVPN server
    "34.36.133.15",  # example AI provider endpoint — customise for your setup
    "188.40.170.101",  # Tor obfs4 relay
    "185.117.73.71",  # Tor obfs4 relay
    "34.111.60.239",  # Google Cloud (ollama.com related)
    "142.251.29.157",  # Google (1e100.net)
    "104.18.26.193",  # Cloudflare
}


class AutoBlocker:
    """Automatic IP blocking via iptables (UFW fallback) with whitelist support."""

    def __init__(self, on_block: Any = None, on_unblock: Any = None) -> None:
        self.on_block = on_block      # callback: async def fn(ip, reason)
        self.on_unblock = on_unblock  # callback: async def fn(ip, reason)
        self._whitelist: set[str] = set(DEFAULT_WHITELIST)
        self._blocked_ips: dict[str, dict] = {}  # ip → {timestamp, reason, severity}
        self._detection_counts: dict[str, int] = {}  # ip → detection count since last block
        self._block_method: str | None = None  # 'ufw', 'iptables', or None if not available yet
        self._load_whitelist_from_neo4j()

    def _detect_block_method(self) -> str | None:
        """Detect available firewall tool (cache result)."""
        if self._block_method is not None:
            return self._block_method
        import shutil
        if shutil.which("ufw"):
            self._block_method = "ufw"
        elif shutil.which("iptables"):
            self._block_method = "iptables"
        else:
            self._block_method = None
            logger.error("Sentinel: no firewall tool available (ufw/iptables not found)")
        return self._block_method

    # ── Whitelist management ─────────────────────────────────────

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted (direct match or CIDR)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for entry in self._whitelist:
            try:
                if "/" in entry:
                    network = ipaddress.ip_network(entry, strict=False)
                    if addr in network:
                        return True
                else:
                    if ip == entry:
                        return True
            except ValueError:
                continue
        return False

    def add_to_whitelist(self, ip: str) -> bool:
        """Add an IP or CIDR to the whitelist."""
        # Validate
        try:
            if "/" in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("Sentinel: invalid whitelist entry: %s", ip)
            return False

        self._whitelist.add(ip)
        self._persist_whitelist_entry(ip, add=True)

        # If currently blocked, unblock
        if ip in self._blocked_ips:
            asyncio.create_task(self.unblock(ip, reason="whitelisted"))

        logger.info("Sentinel: added %s to whitelist", ip)
        return True

    def remove_from_whitelist(self, ip: str) -> bool:
        """Remove an IP or CIDR from the whitelist."""
        if ip in DEFAULT_WHITELIST:
            logger.warning("Sentinel: cannot remove default whitelist entry: %s", ip)
            return False

        if ip in self._whitelist:
            self._whitelist.remove(ip)
            self._persist_whitelist_entry(ip, add=False)
            logger.info("Sentinel: removed %s from whitelist", ip)
            return True
        return False

    def get_whitelist(self) -> list[str]:
        """Return the current whitelist."""
        return sorted(self._whitelist)

    def _persist_whitelist_entry(self, entry: str, add: bool) -> None:
        """Persist whitelist change to Neo4j."""
        try:
            if add:
                cypher_write(
                    "MERGE (w:Whitelist {entry: $entry}) SET w.added_at = $ts",
                    {"entry": entry, "ts": time.time()},
                )
            else:
                cypher_write(
                    "MATCH (w:Whitelist {entry: $entry}) DELETE w",
                    {"entry": entry},
                )
        except Exception as e:
            logger.error("Sentinel: whitelist persist error: %s", e)

    def _load_whitelist_from_neo4j(self) -> None:
        """Load custom whitelist entries from Neo4j."""
        try:
            results = cypher_read("MATCH (w:Whitelist) RETURN w.entry AS entry")
            for row in results:
                entry = row.get("entry")
                if entry:
                    self._whitelist.add(entry)
            logger.info("Sentinel: loaded %d whitelist entries from Neo4j", len(results))
        except Exception as e:
            logger.debug("Sentinel: could not load whitelist from Neo4j: %s", e)

    # ── Blocking logic ────────────────────────────────────────────

    def should_block(self, ip: str, severity: str, detection_count: int) -> bool:
        """Determine if an IP should be blocked based on severity and detection count."""
        if self.is_whitelisted(ip):
            return False

        if ip in self._blocked_ips:
            return False  # already blocked

        threshold = BLOCK_THRESHOLDS.get(severity, 0)
        if threshold == 0:
            return False

        return detection_count >= threshold

    def record_detection(self, ip: str, severity: str) -> bool:
        """Record a detection for an IP and return True if it should be blocked now."""
        if self.is_whitelisted(ip):
            return False

        if ip in self._blocked_ips:
            return False

        self._detection_counts[ip] = self._detection_counts.get(ip, 0) + 1
        count = self._detection_counts[ip]

        should = self.should_block(ip, severity, count)
        if should:
            logger.info(
                "Sentinel: IP %s reached block threshold (%d detections, severity=%s)",
                ip, count, severity,
            )
        return should

    async def block(self, ip: str, reason: str = "auto") -> bool:
        """Block an IP using UFW. Returns True if successful."""
        if self.is_whitelisted(ip):
            logger.info("Sentinel: skipping block for whitelisted IP %s", ip)
            return False

        if ip in self._blocked_ips:
            logger.debug("Sentinel: IP %s already blocked", ip)
            return True

        # Execute UFW block
        success = await self._ufw_block(ip)
        if not success:
            return False

        self._blocked_ips[ip] = {
            "timestamp": time.time(),
            "reason": reason,
            "method": "ufw",
        }

        # Persist to Neo4j
        self._persist_block(ip, reason, blocked=True)

        logger.warning("Sentinel: 🔒 BLOCKED IP %s — reason: %s", ip, reason)

        if self.on_block:
            try:
                await self.on_block(ip, reason)
            except Exception as e:
                logger.error("Sentinel: block callback error: %s", e)

        return True

    async def unblock(self, ip: str, reason: str = "manual") -> bool:
        """Unblock an IP. Returns True if successful."""
        if ip not in self._blocked_ips:
            logger.debug("Sentinel: IP %s not in blocklist", ip)
            # Still try to remove from firewall in case it was added externally
            await self._remove_all_iptables_rules(ip)
            return True

        # Remove ALL firewall rules for this IP (not just one)
        await self._remove_all_iptables_rules(ip)

        # Always clear internal state, even if firewall cleanup had issues
        del self._blocked_ips[ip]
        self._detection_counts.pop(ip, None)

        # Persist to Neo4j
        self._persist_block(ip, reason, blocked=False)

        logger.info("Sentinel: 🔓 UNBLOCKED IP %s — reason: %s", ip, reason)

        if self.on_unblock:
            try:
                await self.on_unblock(ip, reason)
            except Exception as e:
                logger.error("Sentinel: unblock callback error: %s", e)

        return True

    def get_blocked_ips(self) -> list[dict]:
        """Return list of currently blocked IPs."""
        return [
            {"ip": ip, **info}
            for ip, info in self._blocked_ips.items()
        ]

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return ip in self._blocked_ips

    def reset_detection_count(self, ip: str) -> None:
        """Reset detection count for an IP (e.g., after manual review)."""
        self._detection_counts.pop(ip, None)

    # ── UFW integration ──────────────────────────────────────────

    async def _ufw_block(self, ip: str) -> bool:
        """Execute firewall deny rule for an IP."""
        method = self._detect_block_method()
        if method is None:
            return False
        try:
            if method == "ufw":
                proc = await asyncio.create_subprocess_exec(
                    "ufw", "insert", "1", "deny", "from", ip, "to", "any",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:  # iptables
                proc = await asyncio.create_subprocess_exec(
                    "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True
            else:
                logger.error(
                    "Sentinel: %s block failed for %s: %s",
                    method.upper(), ip, stderr.decode().strip() if stderr else "unknown error",
                )
                return False
        except Exception as e:
            logger.error("Sentinel: block error for %s: %s", ip, e)
            return False

    async def _ufw_unblock(self, ip: str) -> bool:
        """Remove firewall deny rule for an IP."""
        method = self._detect_block_method()
        if method is None:
            return False
        try:
            if method == "ufw":
                proc = await asyncio.create_subprocess_exec(
                    "ufw", "delete", "deny", "from", ip, "to", "any",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:  # iptables
                proc = await asyncio.create_subprocess_exec(
                    "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True
            else:
                logger.error(
                    "Sentinel: %s unblock failed for %s: %s",
                    method.upper(), ip, stderr.decode().strip() if stderr else "unknown error",
                )
                return False
        except Exception as e:
            logger.error("Sentinel: unblock error for %s: %s", ip, e)
            return False

    async def _remove_all_iptables_rules(self, ip: str) -> None:
        """Remove ALL iptables rules for an IP (handles duplicate rules from repeated blocks)."""
        while True:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    break  # No more rules to remove
            except Exception:
                break


    # ── Neo4j persistence ─────────────────────────────────────────

    def _persist_block(self, ip: str, reason: str, blocked: bool) -> None:
        """Persist block/unblock action to Neo4j."""
        try:
            if blocked:
                cypher_write(
                    """
                    MATCH (a:Attacker {ip: $ip})
                    SET a.is_blocked = true, a.blocked_at = $ts, a.block_reason = $reason
                    WITH a
                    CREATE (b:BlockAction {ip: $ip, timestamp: $ts, reason: $reason, action: 'block'})
                    CREATE (a)-[:BLOCKED_BY]->(b)
                    """,
                    {"ip": ip, "ts": time.time(), "reason": reason},
                )
            else:
                cypher_write(
                    """
                    MATCH (a:Attacker {ip: $ip})
                    SET a.is_blocked = false, a.unblocked_at = $ts
                    WITH a
                    CREATE (b:BlockAction {ip: $ip, timestamp: $ts, reason: $reason, action: 'unblock'})
                    CREATE (a)-[:UNBLOCKED_BY]->(b)
                    """,
                    {"ip": ip, "ts": time.time(), "reason": reason},
                )
        except Exception as e:
            logger.error("Sentinel: Neo4j block persist error: %s", e)

    def load_blocked_from_neo4j(self) -> None:
        """Load currently blocked IPs from Neo4j on startup."""
        try:
            results = cypher_read(
                "MATCH (a:Attacker) WHERE a.is_blocked = true RETURN a.ip AS ip, a.blocked_at AS ts, a.block_reason AS reason"
            )
            for row in results:
                ip = row.get("ip")
                if ip and ip not in self._blocked_ips:
                    self._blocked_ips[ip] = {
                        "timestamp": row.get("ts", time.time()),
                        "reason": row.get("reason", "loaded_from_neo4j"),
                        "method": "ufw",
                    }
            logger.info("Sentinel: loaded %d blocked IPs from Neo4j", len(self._blocked_ips))
        except Exception as e:
            logger.debug("Sentinel: could not load blocked IPs from Neo4j: %s", e)