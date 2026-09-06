"""Sentinel Engine — main orchestrator for the PITBULL attack detection system.

Coordinates log monitoring, attack detection, and auto-blocking in a single
async lifecycle. Provides stats, threat level computation, and SSE streaming.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from app.core.database import cypher_write, cypher_read
from app.core.sentinel.attack_detector import AttackDetector, AttackEvent
from app.core.sentinel.auto_blocker import AutoBlocker
from app.core.sentinel.response_engine import response_engine
from app.core.sentinel.vigil_bridge import VigilBridge
from app.core.sentinel.log_monitor import LogMonitor

logger = logging.getLogger(__name__)

# Labyrinth integration — set by main.py on startup
_labyrinth_callback = None

def set_labyrinth_callback(callback):
    """Register a callback to be called when Sentinel detects an attack.
    Used by Labyrinth to feed attack events into its recon detector."""
    global _labyrinth_callback
    _labyrinth_callback = callback
    logger.info("Sentinel: Labyrinth bridge connected")

# ── Threat levels ─────────────────────────────────────────────────
NORMAL = "NORMAL"
SUSPICIOUS = "SUSPICIOUS"
ELEVATED = "ELEVATED"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

# Threat level thresholds based on recent activity (last 5 minutes)
THREAT_WINDOW = 300  # 5 minutes


class SentinelEngine:
    """Singleton orchestrator for Sentinel attack detection.

    Usage::

        from app.core.sentinel import SentinelEngine
        engine = SentinelEngine()
        await engine.start()
    """

    _instance: SentinelEngine | None = None

    def __new__(cls) -> SentinelEngine:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self._running = False
        self._total_events = 0
        self._total_attacks = 0
        self._recent_events: list[dict] = []  # ring buffer of recent events
        self._recent_attacks: list[AttackEvent] = []
        self._max_recent = 500

        # SSE subscriber queues
        self._subscribers: list[asyncio.Queue] = []

        # Components
        self._monitor = LogMonitor(event_callback=self._on_raw_event)
        self._detector = AttackDetector(on_attack=self._on_attack)
        self._blocker = AutoBlocker(
            on_block=self._on_ip_blocked,
            on_unblock=self._on_ip_unblocked,
        )

    # ── Lifecycle ───────────────────────────────────────────────

    async def start(self) -> None:
        """Start the Sentinel engine: init Neo4j schema, load state, begin monitoring."""
        if self._running:
            logger.warning("Sentinel: already running")
            return

        logger.info("Sentinel: initializing Neo4j schema...")
        self._init_neo4j_schema()

        # Load persisted state
        self._detector.load_from_neo4j()
        self._blocker.load_blocked_from_neo4j()

        # Start log monitors
        await self._monitor.start()

        # Start response engine
        await response_engine.start()

        # Start VIGIL bridge (feeds kernel alerts into detection + response)
        self._vigil_bridge = VigilBridge(on_alert=self._on_vigil_alert)
        asyncio.create_task(self._vigil_bridge.start())

        self._running = True
        logger.info("Sentinel engine started ✅")

    async def stop(self) -> None:
        """Stop the Sentinel engine."""
        if not self._running:
            return
        self._running = False
        await self._monitor.stop()
        await response_engine.stop()
        if hasattr(self, '_vigil_bridge'):
            await self._vigil_bridge.stop()
        logger.info("Sentinel engine stopped")

    # ── Event processing ─────────────────────────────────────────

    def _on_raw_event(self, event: dict, source: str) -> None:
        """Callback from LogMonitor — called synchronously from the tailer."""
        self._total_events += 1
        self._recent_events.append({"source": source, **event})
        if len(self._recent_events) > self._max_recent:
            self._recent_events = self._recent_events[-self._max_recent:]

        # Push to SSE subscribers
        self._push_to_subscribers({"type": "event", "source": source, **event})

        # Feed to detector (sync — returns AttackEvent or None)
        detection = self._detector.process_event(event)
        if detection:
            self._handle_detection(detection)

    def _on_vigil_alert(self, event: dict) -> None:
        """Handle a VIGIL alert (kernel-level detection from eBPF) or Suricata IDS alert."""
        if not self._running:
            return

        # Check whitelist BEFORE pushing to feed — don't show alerts from our own network
        source_ip = event.get("source_ip", "")
        if source_ip and self._blocker.is_whitelisted(source_ip):
            logger.debug("Sentinel: ignoring whitelisted IP %s (%s)", source_ip, event.get("details", {}).get("attack_type", "unknown"))
            return

        self._total_events += 1
        self._recent_events.append({"source": "vigil", **event})
        if len(self._recent_events) > self._max_recent:
            self._recent_events = self._recent_events[-self._max_recent:]

        self._push_to_subscribers({"type": "vigil_alert", **event})

        # Try detector first
        detection = self._detector.process_event(event)
        if detection:
            self._handle_detection(detection)
        else:
            # VIGIL alerts may not match existing detector patterns — create directly
            attack_type = event.get("details", {}).get("attack_type", "network_anomaly")
            severity = event.get("details", {}).get("severity", "MEDIUM")
            detection = AttackEvent(
                source_ip=event.get("source_ip", "0.0.0.0"),
                attack_type=attack_type,
                severity=severity,
                evidence=[event],
                details=event.get("details", {}),
            )
            self._handle_detection(detection)

    def _on_attack(self, event: AttackEvent) -> None:
        """Callback from AttackDetector for async notification."""
        # This is called if AttackDetector uses async callback
        pass

    def _handle_detection(self, event: AttackEvent) -> None:
        """Handle a detected attack: record, notify, auto-block, and trigger response engine."""
        # Skip whitelisted IPs (localhost, private networks, link-local)
        if self._blocker.is_whitelisted(event.source_ip):
            logger.debug("Sentinel: ignoring event from whitelisted IP %s (%s)", event.source_ip, event.attack_type)
            return

        self._total_attacks += 1
        self._recent_attacks.append(event)
        if len(self._recent_attacks) > self._max_recent:
            self._recent_attacks = self._recent_attacks[-self._max_recent:]

        event_dict = event.to_dict()
        self._push_to_subscribers({"type": "attack", **event_dict})

        # Auto-block check
        should_block = self._blocker.record_detection(event.source_ip, event.severity)
        if should_block:
            reason = f"auto-block: {event.attack_type} (severity={event.severity})"
            asyncio.create_task(self._blocker.block(event.source_ip, reason))

        # ── Feed into Response Engine ──
        asyncio.create_task(response_engine.handle_attack(event_dict))

        logger.warning(
            "Sentinel: 🚨 ATTACK DETECTED — %s from %s (severity=%s, technique=%s)",
            event.attack_type, event.source_ip, event.severity, event.technique_id,
        )

        # ── Feed into Labyrinth recon detector ──
        if _labyrinth_callback:
            try:
                _labyrinth_callback(event)
            except Exception as e:
                logger.warning("Sentinel: Labyrinth bridge error: %s", e, exc_info=True)

    async def _on_ip_blocked(self, ip: str, reason: str) -> None:
        """Callback when an IP is blocked."""
        self._push_to_subscribers({
            "type": "block",
            "ip": ip,
            "reason": reason,
            "timestamp": time.time(),
        })

    async def _on_ip_unblocked(self, ip: str, reason: str) -> None:
        """Callback when an IP is unblocked."""
        self._push_to_subscribers({
            "type": "unblock",
            "ip": ip,
            "reason": reason,
            "timestamp": time.time(),
        })

    # ── SSE subscribers ──────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to real-time Sentinel events via SSE. Returns a Queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove a subscriber queue."""
        if q in self._subscribers:
            self._subscribers.remove(q)

    def _push_to_subscribers(self, data: dict) -> None:
        """Push an event to all SSE subscribers (non-blocking)."""
        for q in self._subscribers:
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                # Drop oldest and retry
                try:
                    q.get_nowait()
                    q.put_nowait(data)
                except Exception:
                    pass

    # ── Stats and threat level ─────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return current engine statistics."""
        now = time.time()
        recent_attack_count = sum(
            1 for a in self._recent_attacks
            if now - a.timestamp < THREAT_WINDOW
        )
        active_attackers = len([
            ip for ip, p in self._detector.attackers.items()
            if now - p.last_seen < THREAT_WINDOW
        ])

        return {
            "total_events": self._total_events,
            "total_attacks": self._total_attacks,
            "recent_attacks": recent_attack_count,
            "blocked_ips": len(self._blocker.get_blocked_ips()),
            "active_attackers": active_attackers,
            "known_attackers": len(self._detector.attackers),
            "threat_level": self._compute_threat_level(recent_attack_count, active_attackers),
            "running": self._running,
        }

    def _compute_threat_level(self, recent_attacks: int, active_attackers: int) -> str:
        """Compute current threat level based on recent activity."""
        if recent_attacks >= 20 or active_attackers >= 10:
            return CRITICAL
        if recent_attacks >= 10 or active_attackers >= 5:
            return HIGH
        if recent_attacks >= 3 or active_attackers >= 2:
            return ELEVATED
        if recent_attacks >= 1 or active_attackers >= 1:
            return SUSPICIOUS
        return NORMAL

    def get_recent_attacks(self, limit: int = 50) -> list[dict]:
        """Return recent attack events."""
        return [a.to_dict() for a in self._recent_attacks[-limit:]]

    def get_attackers(self) -> list[dict]:
        """Return known attacker profiles."""
        return self._detector.get_attackers()

    def get_blocked_ips(self) -> list[dict]:
        """Return currently blocked IPs."""
        return self._blocker.get_blocked_ips()

    # ── Manual actions ─────────────────────────────────────────

    async def block_ip(self, ip: str, reason: str = "manual") -> dict[str, Any]:
        """Manually block an IP."""
        if self._blocker.is_whitelisted(ip):
            return {"success": False, "error": "IP is whitelisted — cannot block"}
        success = await self._blocker.block(ip, reason)
        if success:
            self._detector.update_attacker_blocked(ip, True)
        return {"success": success, "ip": ip, "reason": reason}

    async def unblock_ip(self, ip: str, reason: str = "manual") -> dict[str, Any]:
        """Manually unblock an IP."""
        success = await self._blocker.unblock(ip, reason)
        if success:
            self._detector.update_attacker_blocked(ip, False)
        return {"success": success, "ip": ip, "reason": reason}

    def get_whitelist(self) -> list[str]:
        """Return whitelisted IPs/CIDRs."""
        return self._blocker.get_whitelist()

    def add_whitelist(self, ip: str) -> bool:
        """Add IP to whitelist."""
        return self._blocker.add_to_whitelist(ip)

    def remove_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist."""
        return self._blocker.remove_from_whitelist(ip)

    # ── Neo4j schema ────────────────────────────────────────────

    def _init_neo4j_schema(self) -> None:
        """Initialize Sentinel-specific Neo4j constraints and indexes."""
        constraints = [
            "CREATE CONSTRAINT attacker_ip IF NOT EXISTS FOR (a:Attacker) REQUIRE a.ip IS UNIQUE",
            "CREATE CONSTRAINT attack_event_id IF NOT EXISTS FOR (e:AttackEvent) REQUIRE e.id IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX attack_event_timestamp IF NOT EXISTS FOR (e:AttackEvent) ON (e.timestamp)",
            "CREATE INDEX attack_event_severity IF NOT EXISTS FOR (e:AttackEvent) ON (e.severity)",
            "CREATE INDEX attack_event_type IF NOT EXISTS FOR (e:AttackEvent) ON (e.attack_type)",
            "CREATE INDEX attacker_last_seen IF NOT EXISTS FOR (a:Attacker) ON (a.last_seen)",
            "CREATE INDEX block_action_ip IF NOT EXISTS FOR (b:BlockAction) ON (b.ip)",
        ]
        try:
            for stmt in constraints:
                try:
                    cypher_write(stmt)
                except Exception as e:
                    logger.debug("Sentinel: constraint skipped: %s", e)
            for stmt in indexes:
                try:
                    cypher_write(stmt)
                except Exception as e:
                    logger.debug("Sentinel: index skipped: %s", e)
            logger.info("Sentinel: Neo4j schema initialized (%d constraints, %d indexes)", len(constraints), len(indexes))
        except Exception as e:
            logger.error("Sentinel: Neo4j schema init error: %s", e)

# Module-level singleton
sentinel_engine = SentinelEngine()
