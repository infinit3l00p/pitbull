"""Labyrinth Controller — orchestrates the entire EPHEMERAL LABYRINTH system.

This is the brain that connects all five pillars:
1. MirrorGraph Engine — generates the fake infrastructure
2. Consistency Validator — ensures it's believable
3. Reconnaissance Detector — triggers the system on attacker activity
4. Epistemic Erosion Engine — degrades attacker confidence over time
5. Hypergame Controller — steers the attacker through engineered paths

The controller manages the lifecycle:
- IDLE: System is passive, MirrorGraph not yet generated
- ARMING: MirrorGraph is being generated and validated
- ACTIVE: MirrorGraph is live, recon detector is watching
- ENGAGED: Attacker is interacting with the MirrorGraph
- ERoding: Attacker confidence is being actively degraded
- POST_INCIDENT: Attacker has left, analyzing the engagement

Academic basis:
- Kulkarni & Fu 2020: hypergame controller synthesizes defense strategy
- Ma et al. 2023: optimal resource allocation for proactive defense
- Dykstra & Shortridge 2022: sludge should be deployed "before, during, and after"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from app.labyrinth.mirror_graph import get_mirror_engine, MirrorGraphEngine
from app.labyrinth.consistency_validator import get_consistency_validator, ConsistencyValidator, ValidationResult
from app.labyrinth.recon_detector import get_recon_detector, ReconnaissanceDetector, AttackerProfile, ThreatLevel
from app.labyrinth.erosion_engine import get_erosion_engine, EpistemicErosionEngine, ErosionPhase

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
#  SYSTEM STATE
# ═══════════════════════════════════════════════════════════════════════

class LabyrinthState(str, Enum):
    """Lifecycle states of the EPHEMERAL LABYRINTH system."""
    IDLE = "idle"                    # Not yet armed
    ARMING = "arming"                # Generating MirrorGraph
    ACTIVE = "active"                # Armed, watching for attackers
    ENGAGED = "engaged"              # Attacker is in the MirrorGraph
    ERODING = "eroding"              # Actively eroding attacker confidence
    POST_INCIDENT = "post_incident"  # Engagement over, analyzing


@dataclass
class LabyrinthStats:
    """Statistics for the entire EPHEMERAL LABYRINTH system."""
    state: LabyrinthState = LabyrinthState.IDLE
    mirror_nodes: int = 0
    mirror_edges: int = 0
    validation_result: Optional[ValidationResult] = None
    attackers_tracked: int = 0
    active_attackers: int = 0
    fake_successes_served: int = 0
    dead_ends_served: int = 0
    confidence_crises_detected: int = 0
    abandonment_predictions: int = 0
    mode: str = "idle"  # "mirror", "synthetic", or "idle"
    activated_at: Optional[datetime] = None
    last_engagement: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "mode": self.mode,
            "mirror_nodes": self.mirror_nodes,
            "mirror_edges": self.mirror_edges,
            "validation": self.validation_result.summary() if self.validation_result else None,
            "validation_critical": self.validation_result.critical_count if self.validation_result else 0,
            "validation_high": self.validation_result.high_count if self.validation_result else 0,
            "attackers_tracked": self.attackers_tracked,
            "active_attackers": self.active_attackers,
            "fake_successes_served": self.fake_successes_served,
            "dead_ends_served": self.dead_ends_served,
            "confidence_crises": self.confidence_crises_detected,
            "abandonment_predictions": self.abandonment_predictions,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "last_engagement": self.last_engagement.isoformat() if self.last_engagement else None,
        }


# ═══════════════════════════════════════════════════════════════════════
#  LABYRINTH CONTROLLER
# ═══════════════════════════════════════════════════════════════════════

class LabyrinthController:
    """Orchestrates the entire EPHEMERAL LABYRINTH system.

    Usage:
        controller = get_labyrinth_controller()
        await controller.arm(scale=1.0)  # Generate and validate MirrorGraph
        # System is now ACTIVE — recon detector is watching
        # When an attacker is detected, the system automatically engages
    """

    def __init__(self) -> None:
        self.mirror_engine = get_mirror_engine()
        self.validator = get_consistency_validator()
        self.recon_detector = get_recon_detector()
        self.erosion_engine = get_erosion_engine()

        self._state = LabyrinthState.IDLE
        self._mode = "idle"  # "mirror", "synthetic", or "idle"
        self._stats = LabyrinthStats()
        self._engagement_log: list[dict[str, Any]] = []
        self._system_log: list[dict[str, Any]] = []  # broadcast log for SSE stream
        self._log_subscribers: list = []  # asyncio.Queue instances for SSE

        # Wire up recon detector → controller
        self.recon_detector.set_labyrinth_engine(self)

    @property
    def state(self) -> LabyrinthState:
        return self._state

    @property
    def stats(self) -> LabyrinthStats:
        return self._stats

    # ── LIFECYCLE ──────────────────────────────────────────────────────

    def arm(self, scale: float = 1.0) -> dict[str, Any]:
        """Arm the Labyrinth: generate MirrorGraph + validate consistency.

        If the TrueGraph has real assets, mirror them. If it's empty,
        generate a fully synthetic infrastructure from built-in templates.

        Args:
            scale: Mirror size multiplier (1.0 = 1:1 with TrueGraph)

        Returns:
            Dictionary with generation stats and validation results
        """
        logger.info("EPHEMERAL LABYRINTH: ═══ ARMING SYSTEM ═══")
        self.emit_log("INFO", "═══ ARMING SYSTEM ═══")
        self._state = LabyrinthState.ARMING
        self._stats.state = self._state

        # Step 1: Generate MirrorGraph (mirror real data, or synthesize if empty)
        logger.info("EPHEMERAL LABYRINTH: Step 1/2 — Generating MirrorGraph (scale=%.1f)", scale)
        gen_stats = self.mirror_engine.generate_mirror(scale=scale)
        if "error" in gen_stats:
            # TrueGraph is empty — fall back to synthetic generation
            logger.info("EPHEMERAL LABYRINTH: TrueGraph empty — switching to SYNTHETIC mode")
            self.emit_log("INFO", "TrueGraph empty — switching to SYNTHETIC mode")
            self._mode = "synthetic"
            gen_stats = self.mirror_engine.generate_synthetic(scale=scale)
            if "error" in gen_stats:
                self._state = LabyrinthState.IDLE
                self._stats.state = self._state
                logger.error("EPHEMERAL LABYRINTH: Arming failed — %s", gen_stats["error"])
                return {"error": gen_stats["error"]}
        else:
            self._mode = "mirror"
            self.emit_log("INFO", f"Mirroring TrueGraph — {gen_stats.get('mirror_nodes_total', 0)} nodes")

        self._stats.mode = self._mode
        self._stats.mirror_nodes = gen_stats.get("mirror_nodes_total", 0)
        self._stats.mirror_edges = gen_stats.get("mirror_rels_total", 0)
        self.emit_log("INFO", f"MirrorGraph generated — {self._stats.mirror_nodes} nodes, {self._stats.mirror_edges} edges (mode: {self._mode})")

        # Step 2: Validate consistency
        logger.info("EPHEMERAL LABYRINTH: Step 2/2 — Validating MirrorGraph consistency")
        validation = self.validator.validate()
        self._stats.validation_result = validation

        if not validation.is_valid:
            logger.error(
                "EPHEMERAL LABYRINTH: ❌ Validation FAILED — %d critical, %d high violations",
                validation.critical_count, validation.high_count,
            )
            self.emit_log("WARN", f"Validation FAILED — {validation.critical_count} critical, {validation.high_count} high violations")
            for v in validation.violations:
                if v.severity in ("critical", "high"):
                    logger.error(
                        "EPHEMERAL LABYRINTH: Violation [%s] %s: %s",
                        v.severity, v.check, v.details,
                    )
        else:
            logger.info(
                "EPHEMERAL LABYRINTH: ✅ Validation PASSED — %s",
                validation.summary(),
            )
            self.emit_log("INFO", f"Validation PASSED — {validation.summary()}")

        # Activate
        self._state = LabyrinthState.ACTIVE
        self._stats.state = self._state
        self._stats.activated_at = datetime.now(timezone.utc)

        logger.info(
            "EPHEMERAL LABYRINTH: ═══ SYSTEM ACTIVE ═══ "
            "MirrorGraph: %d nodes, %d edges | "
            "Validation: %s | "
            "Watching for attackers...",
            self._stats.mirror_nodes, self._stats.mirror_edges,
            "PASS" if validation.is_valid else f"FAIL ({validation.critical_count} critical)",
        )
        self.emit_log("INFO", f"═══ SYSTEM ACTIVE ═══ Mode: {self._mode} | Watching for attackers...")

        return {
            "state": self._state.value,
            "mirror_stats": gen_stats,
            "validation": validation.summary(),
            "validation_violations": [
                {"check": v.check, "severity": v.severity, "details": v.details}
                for v in validation.violations if v.severity in ("critical", "high")
            ],
        }

    def disarm(self) -> dict[str, Any]:
        """Disarm the Labyrinth: clear MirrorGraph and reset state."""
        logger.info("EPHEMERAL LABYRINTH: Disarming system...")
        self.emit_log("INFO", "═══ DISARMING SYSTEM ═══")
        cleared = self.mirror_engine.clear_mirror()
        self.recon_detector.reset()
        self.erosion_engine.get_all_states  # just access to reset
        self._erosion_states_backup = list(self.erosion_engine.get_all_states())
        self.erosion_engine._states.clear()

        old_state = self._state
        self._state = LabyrinthState.IDLE
        self._mode = "idle"
        self._stats = LabyrinthStats()

        logger.info("EPHEMERAL LABYRINTH: System disarmed — cleared %d mirror nodes", cleared)
        self.emit_log("INFO", f"System disarmed — cleared {cleared} mirror nodes")
        return {"cleared_nodes": cleared, "previous_state": old_state.value}

    def get_mirror(self) -> dict[str, Any]:
        """Return the current MirrorGraph for inspection."""
        return self.mirror_engine.get_mirror_subgraph()

    def validate(self) -> ValidationResult:
        """Re-run validation on the current MirrorGraph."""
        result = self.validator.validate()
        self._stats.validation_result = result
        return result

    # ── ATTACKER ENGAGEMENT ───────────────────────────────────────────

    def on_recon_detected(self, profile: AttackerProfile) -> None:
        """Called by the recon detector when reconnaissance is confirmed."""
        logger.warning(
            "EPHEMERAL LABYRINTH: 🎯 Attacker detected — %s (threat: %s, tools: %s)",
            profile.source_ip, profile.threat_level.value, profile.tools_detected,
        )
        self.emit_log("WARN", f"🎯 Attacker detected — {profile.source_ip} (threat: {profile.threat_level.value}, tools: {profile.tools_detected})")

        self._state = LabyrinthState.ENGAGED
        self._stats.state = self._state
        self._stats.attackers_tracked += 1
        self._stats.active_attackers = len(self.recon_detector.get_all_attackers())
        self._stats.last_engagement = datetime.now(timezone.utc)

        # Log the engagement
        self._engagement_log.append({
            "event": "attacker_detected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attacker": profile.to_dict(),
        })

        # Initialize erosion state for this attacker
        erosion_state = self.erosion_engine.get_state(profile.source_ip)
        if erosion_state.phase == ErosionPhase.UNAWARE:
            erosion_state.phase = ErosionPhase.ENGAGED
        logger.info(
            "EPHEMERAL LABYRINTH: Erosion engine initialized for %s — phase: %s, confidence: %.0f%%",
            profile.source_ip, erosion_state.phase.value, erosion_state.confidence * 100,
        )

    def serve_interaction(self, attacker_ip: str, context: Optional[dict] = None) -> dict[str, Any]:
        """Serve the next interaction to an attacker.

        This is called when the attacker makes a request that hits the MirrorGraph.
        The controller decides whether to serve a fake success or a dead end
        based on the erosion engine's strategy.
        """
        action = self.erosion_engine.get_next_action(attacker_ip)

        if action == "fake_success":
            interaction = self.erosion_engine.generate_fake_success(attacker_ip, context=context)
            self._stats.fake_successes_served += 1
            self.emit_log("INFO", f"✅ FAKE SUCCESS served to {attacker_ip} — type: {interaction.success_type.value}, confidence: {interaction.confidence_after*100:.0f}%")

            state = self.erosion_engine.get_state(attacker_ip)
            if state.crisis_detected and not self._stats.confidence_crises_detected:
                self._stats.confidence_crises_detected += 1

            return {
                "action": "fake_success",
                "interaction_id": interaction.interaction_id,
                "success_type": interaction.success_type.value,
                "response": interaction.details,
                "attacker_confidence": interaction.confidence_after,
            }

        elif action == "dead_end":
            response = self.erosion_engine.generate_dead_end(attacker_ip, context=context)
            self._stats.dead_ends_served += 1
            self.emit_log("INFO", f"❌ DEAD END served to {attacker_ip}")

            state = self.erosion_engine.get_state(attacker_ip)
            if state.crisis_detected:
                self._stats.confidence_crises_detected = max(self._stats.confidence_crises_detected, 1)
            if state.abandonment_predicted:
                self._stats.abandonment_predictions += 1
                self._log_engagement(attacker_ip, "abandonment_predicted", state.to_dict())

            return {
                "action": "dead_end",
                "response": response,
                "attacker_confidence": response.get("_meta", {}).get("attacker_confidence_after", 0),
            }

        elif action == "log_and_analyze":
            self._state = LabyrinthState.POST_INCIDENT
            self._stats.state = self._state
            self._log_engagement(attacker_ip, "engagement_ended", {})
            return {"action": "log", "message": "Engagement ended, analyzing"}

        return {"action": "wait", "message": "System is waiting"}

    # ── EVENT INGESTION (delegate to recon detector) ──────────────────

    def process_connection(self, source_ip: str, dest_port: int, protocol: str = "tcp") -> Optional[dict]:
        """Process a network connection event."""
        event = self.recon_detector.process_connection(source_ip, dest_port, protocol)
        if event:
            self.emit_log("INFO", f"Connection from {source_ip}:{dest_port}/{protocol} — recon detected: {event.recon_type.value}")
            return {
                "event_type": event.recon_type.value,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "confidence": event.confidence,
                "details": event.details,
            }
        return None

    def process_dns(self, source_ip: str, query: str, query_type: str = "A") -> Optional[dict]:
        """Process a DNS query event."""
        event = self.recon_detector.process_dns(source_ip, query, query_type)
        if event:
            self.emit_log("INFO", f"DNS query from {source_ip}: {query} ({query_type}) — recon detected: {event.recon_type.value}")
            return {
                "event_type": event.recon_type.value,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "confidence": event.confidence,
                "details": event.details,
            }
        return None

    def process_http(self, source_ip: str, method: str, path: str, user_agent: str = "") -> Optional[dict]:
        """Process an HTTP request event."""
        event = self.recon_detector.process_http(source_ip, method, path, user_agent)
        if event:
            self.emit_log("INFO", f"HTTP {method} {path} from {source_ip} — recon detected: {event.recon_type.value}")
            return {
                "event_type": event.recon_type.value,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "confidence": event.confidence,
                "details": event.details,
            }
        return None

    def process_shell(self, source_ip: str, command: str) -> Optional[dict]:
        """Process a shell command event."""
        event = self.recon_detector.process_shell(source_ip, command)
        if event:
            self.emit_log("WARN", f"Shell command from {source_ip}: {command[:50]} — recon detected: {event.recon_type.value}")
            return {
                "event_type": event.recon_type.value,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "confidence": event.confidence,
                "details": event.details,
            }
        return None

    def process_auth(self, source_ip: str, username: str, success: bool, service: str = "ssh") -> Optional[dict]:
        """Process an authentication event."""
        event = self.recon_detector.process_auth(source_ip, username, success, service)
        if event:
            self.emit_log("WARN", f"Auth attempt from {source_ip}: {username}@{service} ({'success' if success else 'failed'}) — recon detected")
            return {
                "event_type": event.recon_type.value,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "confidence": event.confidence,
                "details": event.details,
            }
        return None

    def process_behavior(self, attacker_ip: str, behavior_type: str) -> Optional[dict]:
        """Process a behavioral indicator from the attacker."""
        new_phase = self.erosion_engine.process_behavior(attacker_ip, behavior_type)
        if new_phase:
            self.emit_log("WARN", f"Behavior '{behavior_type}' from {attacker_ip} — phase change: {new_phase.value}")
            self._log_engagement(attacker_ip, f"phase_change_{new_phase.value}", {})
            return {"attacker_ip": attacker_ip, "new_phase": new_phase.value}
        return None

    # ── STATUS & REPORTING ────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Return full system status."""
        attackers = self.recon_detector.get_all_attackers()
        erosion_states = self.erosion_engine.get_all_states()

        # Update stats from recon detector
        self._stats.attackers_tracked = len(attackers)
        self._stats.active_attackers = sum(1 for a in attackers if a.threat_level != ThreatLevel.NORMAL)

        return {
            "labyrinth": self._stats.to_dict(),
            "attackers": [p.to_dict() for p in attackers],
            "erosion_states": [s.to_dict() for s in erosion_states],
            "engagement_log_count": len(self._engagement_log),
        }

    def get_engagement_log(self) -> list[dict[str, Any]]:
        """Return the full engagement log."""
        return list(self._engagement_log)

    # ── INTERNAL ──────────────────────────────────────────────────────

    def _log_engagement(self, attacker_ip: str, event: str, data: dict) -> None:
        """Log an engagement event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attacker_ip": attacker_ip,
            "event": event,
            "data": data,
        }
        self._engagement_log.append(entry)
        self._broadcast_log("engagement", entry)

    def emit_log(self, level: str, message: str, **extra) -> None:
        """Emit a system log event to all SSE subscribers."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            **extra,
        }
        self._system_log.append(entry)
        # Trim to last 500 entries
        if len(self._system_log) > 500:
            self._system_log = self._system_log[-500:]
        self._broadcast_log("system", entry)

    def _broadcast_log(self, event_type: str, entry: dict) -> None:
        """Push a log entry to all SSE subscriber queues."""
        import asyncio
        for queue in self._log_subscribers:
            try:
                queue.put_nowait({"event": event_type, **entry})
            except asyncio.QueueFull:
                pass  # drop if subscriber is slow

    async def subscribe_logs(self):
        """Subscribe to the log stream. Yields dict events."""
        import asyncio
        queue = asyncio.Queue(maxsize=100)
        self._log_subscribers.append(queue)
        try:
            # Send recent system log history first
            for entry in self._system_log[-20:]:
                yield {"event": "system", **entry}
            # Send recent engagement log
            for entry in self._engagement_log[-10:]:
                yield {"event": "engagement", **entry}
            # Stream new events
            while True:
                entry = await queue.get()
                yield entry
        finally:
            self._log_subscribers.remove(queue)

    def get_recent_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent system logs for REST polling fallback."""
        return self._system_log[-limit:]


# ── Singleton ────────────────────────────────────────────────────────────

_controller: Optional[LabyrinthController] = None


def get_labyrinth_controller() -> LabyrinthController:
    global _controller
    if _controller is None:
        _controller = LabyrinthController()
    return _controller