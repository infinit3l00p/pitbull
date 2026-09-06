"""VIGIL Bridge — polls VIGIL's alert API and feeds kernel-level detections into Sentinel.

VIGIL runs as an eBPF detection sensor only (response engine disabled).
This bridge polls /api/alerts every 5 seconds, converts VIGIL alert categories
into Sentinel AttackEvent format, and feeds them through the response engine.

VIGIL categories → PITBULL attack types:
  ROOTKIT              → kernel_rootkit (T1014)
  C2_COMMUNICATION      → c2_communication (T1071)
  CONTAINER_ESCAPE     → container_escape (T1611)
  CRYPTOJACKING         → cryptojacking (T1496)
  DNS_EXFILTRATION      → dns_exfiltration (T1048)
  TTY_SURVEILLANCE      → tty_surveillance (T1057)
  PRIVILEGE_ESCALATION  → privilege_escalation (T1548)
  PROCESS_INJECTION     → process_injection (T1055)
  NETWORK_ANOMALY       → network_anomaly (T1046)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# VIGIL alert API config
VIGIL_HOST = "127.0.0.1"
VIGIL_PORT = 8443
VIGIL_AUTH_TOKEN = ""  # loaded from env
VIGIL_POLL_INTERVAL = 5  # seconds

# Category mapping
VIGIL_CATEGORY_MAP: dict[str, dict[str, str]] = {
    "ROOTKIT": {"attack_type": "kernel_rootkit", "severity": "CRITICAL"},
    "C2_COMMUNICATION": {"attack_type": "c2_communication", "severity": "CRITICAL"},
    "CONTAINER_ESCAPE": {"attack_type": "container_escape", "severity": "CRITICAL"},
    "CRYPTOJACKING": {"attack_type": "cryptojacking", "severity": "HIGH"},
    "DNS_EXFILTRATION": {"attack_type": "dns_exfiltration", "severity": "HIGH"},
    "TTY_SURVEILLANCE": {"attack_type": "tty_surveillance", "severity": "MEDIUM"},
    "PRIVILEGE_ESCALATION": {"attack_type": "privilege_escalation", "severity": "CRITICAL"},
    "PROCESS_INJECTION": {"attack_type": "process_injection", "severity": "CRITICAL"},
    "NETWORK_ANOMALY": {"attack_type": "network_anomaly", "severity": "MEDIUM"},
}


class VigilBridge:
    """Polls VIGIL alerts and feeds them into Sentinel's attack detector."""

    def __init__(self, on_alert: Any = None) -> None:
        self.on_alert = on_alert  # callback: async def fn(event: dict)
        self._running = False
        self._last_alert_time: str = ""  # ISO timestamp of last processed alert
        self._client: httpx.AsyncClient | None = None
        self._stats = {
            "total_polled": 0,
            "total_alerts": 0,
            "total_processed": 0,
            "total_errors": 0,
            "by_category": {},
        }

    async def start(self) -> None:
        """Start polling VIGIL alerts."""
        import os
        global VIGIL_AUTH_TOKEN
        VIGIL_AUTH_TOKEN = os.environ.get("VIGIL_AUTH_TOKEN", "")

        self._running = True
        self._client = httpx.AsyncClient(
            base_url=f"http://{VIGIL_HOST}:{VIGIL_PORT}",
            headers={"Authorization": f"Bearer {VIGIL_AUTH_TOKEN}"} if VIGIL_AUTH_TOKEN else {},
            timeout=10.0,
            trust_env=False,  # localhost-only client — never inherit proxy env (audit Aug 30)
        )
        logger.info("VIGIL Bridge: started — polling %s:%d every %ds", VIGIL_HOST, VIGIL_PORT, VIGIL_POLL_INTERVAL)

        # Initial sync — mark current alerts as seen to avoid replaying old ones
        await self._initial_sync()

        while self._running:
            try:
                await self._poll_once()
            except Exception as e:
                self._stats["total_errors"] += 1
                logger.error("VIGIL Bridge: poll error: %s", e)
            await asyncio.sleep(VIGIL_POLL_INTERVAL)

    async def stop(self) -> None:
        """Stop polling."""
        self._running = False
        if self._client:
            await self._client.aclose()
        logger.info("VIGIL Bridge: stopped")

    async def _initial_sync(self) -> None:
        """Mark existing alerts as seen on startup to avoid replaying."""
        try:
            resp = await self._client.get("/api/alerts")
            if resp.status_code == 200:
                data = resp.json()
                alerts = data.get("alerts", [])
                if alerts:
                    # Set last_alert_time to the most recent alert
                    self._last_alert_time = alerts[-1].get("time", "")
                    logger.info("VIGIL Bridge: initial sync — %d existing alerts marked as seen", len(alerts))
        except Exception as e:
            logger.warning("VIGIL Bridge: initial sync failed: %s", e)

    async def _poll_once(self) -> None:
        """Poll VIGIL for new alerts and process them."""
        self._stats["total_polled"] += 1

        resp = await self._client.get("/api/alerts")
        if resp.status_code != 200:
            logger.warning("VIGIL Bridge: non-200 response: %d", resp.status_code)
            return

        data = resp.json()
        alerts = data.get("alerts", [])
        if not alerts:
            return

        # Filter to only new alerts since last poll
        new_alerts = []
        for alert in alerts:
            alert_time = alert.get("time", "")
            if alert_time > self._last_alert_time:
                new_alerts.append(alert)

        if not new_alerts:
            return

        self._last_alert_time = new_alerts[-1].get("time", self._last_alert_time)
        self._stats["total_alerts"] += len(new_alerts)

        for alert in new_alerts:
            self._process_alert(alert)

    def _process_alert(self, alert: dict) -> None:
        """Convert a VIGIL alert to a Sentinel event and forward."""
        category = alert.get("category", "UNKNOWN")
        mapping = VIGIL_CATEGORY_MAP.get(category)

        if not mapping:
            # Unknown category — log but don't process
            logger.debug("VIGIL Bridge: unknown category '%s' — skipping", category)
            self._stats["by_category"][category] = self._stats["by_category"].get(category, 0) + 1
            return

        attack_type = mapping["attack_type"]
        severity = mapping["severity"]
        self._stats["by_category"][category] = self._stats["by_category"].get(category, 0) + 1

        # Build Sentinel-compatible event
        event = {
            "timestamp": alert.get("time", ""),
            "source_ip": "0.0.0.0",  # VIGIL alerts are local kernel detections — no remote attacker
            "event_type": "vigil_alert",
            "details": {
                "attack_type": attack_type,
                "severity": severity,
                "category": category,
                "message": alert.get("message", "")[:500],
                "pid": alert.get("pid", 0),
                "vigil_severity": alert.get("severity", ""),
            },
            "tags": ["vigil_alert"],
        }

        logger.warning(
            "VIGIL Bridge: %s detected — %s (severity=%s, pid=%s)",
            attack_type, category, severity, alert.get("pid", "?"),
        )

        self._stats["total_processed"] += 1

        if self.on_alert:
            try:
                self.on_alert(event)
            except Exception as e:
                logger.error("VIGIL Bridge: callback error: %s", e)

    def get_stats(self) -> dict:
        """Return bridge statistics."""
        return {
            "running": self._running,
            "poll_interval": VIGIL_POLL_INTERVAL,
            "last_alert_time": self._last_alert_time,
            **self._stats,
        }