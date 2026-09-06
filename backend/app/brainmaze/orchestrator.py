"""BrainMaze Orchestrator — coordinates all confusion components based on attacker behavior.

Monitors attacker progress and selects appropriate confusion techniques.
Escalates confusion over time: false trails → time wasters → paranoia → personas.
Tracks attacker "confusion score" (0-100) and feeds into the Labyrinth erosion engine.

The confusion score is based on:
- Time spent in the system
- Commands retried
- Dead ends hit
- Paranoia indicators (investigating "other attacker" traces)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from app.brainmaze.persona import PersonaEngine, PersonaType, Persona
from app.brainmaze.false_trails import FalseTrailGenerator
from app.brainmaze.paranoia import ParanoiaInducer, ParanoiaLevel, ParanoiaType
from app.brainmaze.time_wasters import TimeWasterGenerator

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
#  CONFUSION ESCALATION PHASES
# ═══════════════════════════════════════════════════════════════════════

class ConfusionPhase(str, Enum):
    """Escalation phases for BrainMaze confusion techniques."""
    PASSIVE = "passive"         # Not yet engaged — waiting for attacker
    TRAILS = "trails"           # Deploying false trails
    WASTERS = "wasters"         # Deploying time wasters
    PARANOIA = "paranoia"       # Injecting paranoia indicators
    PERSONAS = "personas"       # Activating LLM personas
    MAX_CONFUSION = "max_confusion"  # All techniques active, "another hacker" deployed


@dataclass
class ConfusionState:
    """Tracks confusion state for a single attacker."""
    attacker_ip: str
    confusion_score: int = 0  # 0-100
    phase: ConfusionPhase = ConfusionPhase.PASSIVE
    first_seen: Optional[datetime] = None
    last_update: Optional[datetime] = None

    # Behavioral tracking
    time_in_system: int = 0  # seconds
    commands_executed: int = 0
    commands_retried: int = 0
    dead_ends_hit: int = 0
    paranoia_indicators: int = 0  # times attacker investigated "other attacker" traces

    # Active techniques
    active_techniques: list[str] = field(default_factory=list)
    trails_deployed: int = 0
    wasters_deployed: int = 0
    paranoia_injections: int = 0
    persona_active: bool = False
    persona_type: Optional[str] = None

    # History
    technique_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attacker_ip": self.attacker_ip,
            "confusion_score": self.confusion_score,
            "phase": self.phase.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "time_in_system": self.time_in_system,
            "commands_executed": self.commands_executed,
            "commands_retried": self.commands_retried,
            "dead_ends_hit": self.dead_ends_hit,
            "paranoia_indicators": self.paranoia_indicators,
            "active_techniques": self.active_techniques,
            "trails_deployed": self.trails_deployed,
            "wasters_deployed": self.wasters_deployed,
            "paranoia_injections": self.paranoia_injections,
            "persona_active": self.persona_active,
            "persona_type": self.persona_type,
            "technique_history_count": len(self.technique_history),
        }


# ═══════════════════════════════════════════════════════════════════════
#  BRAINMAZE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class BrainMazeOrchestrator:
    """Coordinates all BrainMaze components based on attacker behavior.

    Escalation order: false trails → time wasters → paranoia → personas
    The confusion score (0-100) determines which techniques are active:
    - 0-20:   Passive monitoring
    - 21-40:  False trails deployed
    - 41-60:  Time wasters added
    - 61-80:  Paranoia injection begins
    - 81-100: Full confusion — personas active, "another hacker" deployed
    """

    def __init__(self) -> None:
        self.persona_engine = PersonaEngine()
        self.trail_generator = FalseTrailGenerator()
        self.paranoia_inducer = ParanoiaInducer()
        self.time_waster_gen = TimeWasterGenerator()

        self._states: dict[str, ConfusionState] = {}
        self._system_log: list[dict[str, Any]] = []
        self._log_subscribers: list = []

    # ── STATE MANAGEMENT ─────────────────────────────────────────────

    def get_state(self, attacker_ip: str) -> ConfusionState:
        """Get or create confusion state for an attacker."""
        if attacker_ip not in self._states:
            state = ConfusionState(attacker_ip=attacker_ip)
            state.first_seen = datetime.now(timezone.utc)
            self._states[attacker_ip] = state
            self._log("INFO", f"New attacker tracked: {attacker_ip}")
        return self._states[attacker_ip]

    def get_all_states(self) -> list[ConfusionState]:
        return list(self._states.values())

    # ── BEHAVIOR PROCESSING ─────────────────────────────────────────

    def process_command(self, attacker_ip: str, command: str) -> dict[str, Any]:
        """Process a command from the attacker and update confusion score."""
        state = self.get_state(attacker_ip)
        state.commands_executed += 1
        state.last_update = datetime.now(timezone.utc)

        # Check for paranoia indicators (attacker investigating "other attacker")
        paranoia_keywords = ["who", "users", "last", "w", "finger", "whoami",
                              "history", "ps", "netstat", "ss", "lsof",
                              "crontab", "at", "systemctl list"]
        if any(kw in command.lower() for kw in paranoia_keywords):
            state.paranoia_indicators += 1
            self._log("WARN", f"Paranoia indicator from {attacker_ip}: '{command}' (indicators: {state.paranoia_indicators})")

        # Check for retry behavior
        if hasattr(self, '_last_commands'):
            if attacker_ip in self._last_commands and self._last_commands[attacker_ip] == command:
                state.commands_retried += 1
        if not hasattr(self, '_last_commands'):
            self._last_commands: dict[str, str] = {}
        self._last_commands[attacker_ip] = command

        # Update confusion score
        self._update_confusion_score(state)

        # Check for phase escalation
        self._check_escalation(state)

        return {
            "attacker_ip": attacker_ip,
            "confusion_score": state.confusion_score,
            "phase": state.phase.value,
            "active_techniques": state.active_techniques,
        }

    def process_dead_end(self, attacker_ip: str) -> dict[str, Any]:
        """Record that the attacker hit a dead end."""
        state = self.get_state(attacker_ip)
        state.dead_ends_hit += 1
        state.last_update = datetime.now(timezone.utc)
        self._update_confusion_score(state)
        self._check_escalation(state)
        return state.to_dict()

    def process_time_elapsed(self, attacker_ip: str, seconds: int) -> dict[str, Any]:
        """Record time elapsed for an attacker in the system."""
        state = self.get_state(attacker_ip)
        state.time_in_system += seconds
        state.last_update = datetime.now(timezone.utc)
        self._update_confusion_score(state)
        self._check_escalation(state)
        return state.to_dict()

    # ── CONFUSION SCORE ──────────────────────────────────────────────

    def _update_confusion_score(self, state: ConfusionState) -> None:
        """Calculate confusion score (0-100) based on behavioral indicators.

        Factors:
        - Time in system (longer = more confused, cap at 30 points)
        - Commands retried (each retry = 3 points, cap at 20)
        - Dead ends hit (each = 5 points, cap at 25)
        - Paranoia indicators (each = 4 points, cap at 25)
        """
        time_score = min(30, state.time_in_system // 60)  # 1 point per minute, cap 30
        retry_score = min(20, state.commands_retried * 3)
        dead_end_score = min(25, state.dead_ends_hit * 5)
        paranoia_score = min(25, state.paranoia_indicators * 4)

        state.confusion_score = time_score + retry_score + dead_end_score + paranoia_score

    # ── ESCALATION ───────────────────────────────────────────────────

    def _check_escalation(self, state: ConfusionState) -> None:
        """Check if confusion phase should escalate."""
        old_phase = state.phase

        if state.confusion_score >= 81:
            state.phase = ConfusionPhase.MAX_CONFUSION
        elif state.confusion_score >= 61:
            state.phase = ConfusionPhase.PERSONAS
        elif state.confusion_score >= 41:
            state.phase = ConfusionPhase.WASTERS
        elif state.confusion_score >= 21:
            state.phase = ConfusionPhase.TRAILS
        else:
            state.phase = ConfusionPhase.PASSIVE

        if state.phase != old_phase:
            self._log("WARN", f"Confusion escalation for {state.attacker_ip}: {old_phase.value} → {state.phase.value} (score: {state.confusion_score})")
            self._record_technique(state, "phase_escalation", {
                "from": old_phase.value,
                "to": state.phase.value,
                "confusion_score": state.confusion_score,
            })

            # Auto-deploy techniques for the new phase
            self._auto_deploy(state)

    def _auto_deploy(self, state: ConfusionState) -> None:
        """Automatically deploy techniques when phase changes."""
        ip = state.attacker_ip

        if state.phase == ConfusionPhase.TRAILS and state.trails_deployed == 0:
            # Deploy initial false trails
            self.deploy_false_trails(ip, "credentials")
            self.deploy_false_trails(ip, "history")
            state.active_techniques.append("false_trails")

        elif state.phase == ConfusionPhase.WASTERS and state.wasters_deployed == 0:
            # Deploy time wasters
            self.deploy_time_waster(ip, "filesystem")
            state.active_techniques.append("time_wasters")

        elif state.phase == ConfusionPhase.PERSONAS and state.paranoia_injections == 0:
            # Start paranoia injection
            self.deploy_paranoia(ip, "logs")
            self.deploy_paranoia(ip, "sessions")
            state.active_techniques.append("paranoia")

        elif state.phase == ConfusionPhase.MAX_CONFUSION and not state.persona_active:
            # Deploy "another hacker" persona
            persona = self.persona_engine.select_persona_for_attacker(ip, state.confusion_score)
            state.persona_active = True
            state.persona_type = persona.persona_type.value
            state.active_techniques.append("persona_another_hacker")
            self._log("CRITICAL", f"MAX CONFUSION: Deployed '{persona.name}' persona for {ip}")

    # ── TECHNIQUE DEPLOYMENT ─────────────────────────────────────────

    def deploy_false_trails(self, attacker_ip: str, trail_type: str) -> dict[str, Any]:
        """Deploy a specific type of false trail."""
        state = self.get_state(attacker_ip)
        state.trails_deployed += 1

        if trail_type == "dns":
            result = self.trail_generator.generate_fake_dns("corp.local")
        elif trail_type == "credentials":
            result = self.trail_generator.generate_fake_credentials(count=10)
        elif trail_type == "history":
            result = self.trail_generator.generate_fake_history()
        elif trail_type == "config":
            result = self.trail_generator.generate_fake_config(".env.production")
        elif trail_type == "users":
            result = self.trail_generator.generate_fake_users()
        else:
            return {"error": f"Unknown trail type: {trail_type}"}

        self._record_technique(state, "false_trail", {"trail_type": trail_type, "trail_id": result.get("trail_id")})
        self._log("INFO", f"Deployed false trail ({trail_type}) for {attacker_ip}")
        return result

    def deploy_time_waster(self, attacker_ip: str, waster_type: str) -> dict[str, Any]:
        """Deploy a specific type of time waster."""
        state = self.get_state(attacker_ip)
        state.wasters_deployed += 1

        if waster_type == "database":
            result = self.time_waster_gen.generate_fake_database()
        elif waster_type == "filesystem":
            result = self.time_waster_gen.generate_fake_filesystem()
        elif waster_type == "api_docs":
            result = self.time_waster_gen.generate_fake_api_docs()
        elif waster_type == "source_code":
            result = self.time_waster_gen.generate_fake_source_code()
        elif waster_type == "git_repo":
            result = self.time_waster_gen.generate_fake_git_repo()
        else:
            return {"error": f"Unknown waster type: {waster_type}"}

        self._record_technique(state, "time_waster", {"waster_type": waster_type, "waster_id": result.get("waster_id")})
        self._log("INFO", f"Deployed time waster ({waster_type}) for {attacker_ip}")
        return result

    def deploy_paranoia(self, attacker_ip: str, paranoia_type: str) -> dict[str, Any]:
        """Deploy a specific type of paranoia indicator."""
        state = self.get_state(attacker_ip)
        state.paranoia_injections += 1

        if paranoia_type == "logs":
            result = self.paranoia_inducer.inject_fake_attacker_logs(attacker_ip)
        elif paranoia_type == "sessions":
            result = self.paranoia_inducer.inject_fake_session_indicators(attacker_ip)
        elif paranoia_type == "network":
            result = self.paranoia_inducer.inject_fake_network_connections(attacker_ip)
        elif paranoia_type == "processes":
            result = self.paranoia_inducer.inject_fake_process_list(attacker_ip)
        elif paranoia_type == "crontab":
            result = self.paranoia_inducer.inject_fake_crontab(attacker_ip)
        else:
            return {"error": f"Unknown paranoia type: {paranoia_type}"}

        self._record_technique(state, "paranoia", {"paranoia_type": paranoia_type, "injection_id": result.get("injection_id")})
        self._log("WARN", f"Deployed paranoia indicator ({paranoia_type}) for {attacker_ip}")
        return result

    def deploy_persona(self, attacker_ip: str, persona_type: str | None = None) -> dict[str, Any]:
        """Deploy a persona for an attacker interaction."""
        state = self.get_state(attacker_ip)

        if persona_type:
            try:
                ptype = PersonaType(persona_type)
                persona = self.persona_engine.get_persona(ptype)
            except ValueError:
                return {"error": f"Unknown persona type: {persona_type}"}
        else:
            persona = self.persona_engine.select_persona_for_attacker(attacker_ip, state.confusion_score)

        persona.active = True
        state.persona_active = True
        state.persona_type = persona.persona_type.value

        if "persona" not in state.active_techniques:
            state.active_techniques.append(f"persona_{persona.persona_type.value}")

        self._record_technique(state, "persona_deploy", {"persona": persona.name, "type": persona.persona_type.value})
        self._log("INFO", f"Deployed persona '{persona.name}' ({persona.persona_type.value}) for {attacker_ip}")
        return {
            "persona_name": persona.name,
            "persona_type": persona.persona_type.value,
            "role": persona.role,
            "tone": persona.tone,
            "active": True,
        }

    def generate_persona_response(
        self,
        attacker_ip: str,
        attacker_input: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a response from the active persona for an attacker."""
        state = self.get_state(attacker_ip)
        persona = self.persona_engine.get_active_persona(attacker_ip)

        if persona is None:
            # Auto-select based on confusion score
            persona = self.persona_engine.select_persona_for_attacker(attacker_ip, state.confusion_score)
            state.persona_active = True
            state.persona_type = persona.persona_type.value

        ctx = {"attacker_ip": attacker_ip, "confusion_score": state.confusion_score, **(context or {})}
        response = self.persona_engine.generate_response(persona, attacker_input, ctx)

        self._record_technique(state, "persona_response", {
            "persona": persona.name,
            "input_preview": attacker_input[:100],
            "response_preview": response[:100],
        })

        return {
            "persona_name": persona.name,
            "persona_type": persona.persona_type.value,
            "response": response,
            "interaction_count": persona.interactions,
        }

    # ── STATUS & REPORTING ──────────────────────────────────────────

    def get_confusion_status(self, attacker_ip: str) -> dict[str, Any]:
        """Get current confusion score and active techniques for an attacker."""
        state = self.get_state(attacker_ip)
        return state.to_dict()

    def get_confusion_history(self, attacker_ip: str) -> dict[str, Any]:
        """Get timeline of confusion techniques applied to an attacker."""
        state = self.get_state(attacker_ip)
        return {
            "attacker_ip": attacker_ip,
            "confusion_score": state.confusion_score,
            "phase": state.phase.value,
            "technique_count": len(state.technique_history),
            "history": state.technique_history,
        }

    def get_status(self) -> dict[str, Any]:
        """Get full BrainMaze status."""
        states = self.get_all_states()
        return {
            "total_attackers": len(states),
            "active_attackers": sum(1 for s in states if s.phase != ConfusionPhase.PASSIVE),
            "trails_deployed": sum(s.trails_deployed for s in states),
            "wasters_deployed": sum(s.wasters_deployed for s in states),
            "paranoia_injections": sum(s.paranoia_injections for s in states),
            "active_personas": sum(1 for s in states if s.persona_active),
            "avg_confusion_score": sum(s.confusion_score for s in states) / max(1, len(states)),
            "attackers": [s.to_dict() for s in states],
            "personas": self.persona_engine.get_active_personas_status(),
            "techniques": self._get_available_techniques(),
        }

    def get_analytics(self) -> dict[str, Any]:
        """Get confusion effectiveness statistics."""
        states = self.get_all_states()
        time_stats = self.time_waster_gen.get_time_wasted()

        # Technique effectiveness
        technique_counts: dict[str, int] = {}
        for s in states:
            for t in s.technique_history:
                technique_type = t.get("technique", "unknown")
                technique_counts[technique_type] = technique_counts.get(technique_type, 0) + 1

        return {
            "total_attackers": len(states),
            "total_techniques_deployed": sum(len(s.technique_history) for s in states),
            "avg_confusion_score": sum(s.confusion_score for s in states) / max(1, len(states)),
            "max_confusion_score": max((s.confusion_score for s in states), default=0),
            "total_time_wasted_seconds": time_stats.get("total_time_wasted_seconds", 0),
            "technique_breakdown": technique_counts,
            "phase_distribution": {
                phase.value: sum(1 for s in states if s.phase == phase)
                for phase in ConfusionPhase
            },
            "persona_interactions": len(self.persona_engine.get_interaction_history()),
        }

    def get_techniques(self) -> list[dict[str, Any]]:
        """List all available confusion techniques."""
        return self._get_available_techniques()

    def _get_available_techniques(self) -> list[dict[str, Any]]:
        """Return all available confusion techniques."""
        return [
            {"category": "false_trails", "techniques": [
                {"id": "dns", "name": "Fake DNS Records", "description": "Generate fake DNS records pointing to honeypot IPs"},
                {"id": "credentials", "name": "Fake Credentials", "description": "Generate fake but realistic-looking credentials with canary tokens"},
                {"id": "history", "name": "Fake Bash History", "description": "Generate fake bash_history entries that look real"},
                {"id": "config", "name": "Fake Config Files", "description": "Generate fake config files (.env, config.yml, docker-compose.yml) with canary tokens"},
                {"id": "users", "name": "Fake Users", "description": "Generate fake /etc/passwd entries with realistic usernames"},
            ]},
            {"category": "paranoia", "techniques": [
                {"id": "logs", "name": "Fake Attacker Logs", "description": "Create fake log entries showing 'another attacker' was here"},
                {"id": "sessions", "name": "Fake Session Indicators", "description": "Create fake .bash_history entries from 'another user'"},
                {"id": "network", "name": "Fake Network Connections", "description": "Create fake netstat output showing connections to unknown IPs"},
                {"id": "processes", "name": "Fake Process List", "description": "Create fake ps output showing suspicious processes"},
                {"id": "crontab", "name": "Fake Crontab", "description": "Create fake crontab entries suggesting persistence was already established"},
            ]},
            {"category": "time_wasters", "techniques": [
                {"id": "database", "name": "Fake Database Dump", "description": "Generate fake SQL dump with realistic-looking data"},
                {"id": "filesystem", "name": "Fake Filesystem", "description": "Generate fake directory listing with interesting filenames"},
                {"id": "api_docs", "name": "Fake API Docs", "description": "Generate fake API documentation with endpoints that don't exist"},
                {"id": "source_code", "name": "Fake Source Code", "description": "Generate fake source code with fake vulnerabilities"},
                {"id": "git_repo", "name": "Fake Git Repo", "description": "Generate fake .git directory with fake commit history"},
            ]},
            {"category": "personas", "techniques": [
                {"id": "confused_sysadmin", "name": "Confused Sysadmin", "description": "Dave Mitchell — overwhelmed, gives partial info"},
                {"id": "panicked_helpdesk", "name": "Panicked Helpdesk", "description": "Sarah Chen — nervous, accidentally reveals info"},
                {"id": "incompetent_developer", "name": "Incompetent Developer", "description": "Mike Torres — overconfident, gives incorrect architecture details"},
                {"id": "another_hacker", "name": "Another Hacker", "description": "'r00t' — creates paranoia about who else is in the system"},
            ]},
        ]

    # ── EROSION ENGINE INTEGRATION ──────────────────────────────────

    def feed_erosion_engine(self, attacker_ip: str) -> dict[str, Any]:
        """Feed confusion data into the Labyrinth erosion engine.

        When confusion score is high, this accelerates confidence degradation
        by serving additional dead ends through the erosion engine.
        """
        state = self.get_state(attacker_ip)

        try:
            from app.labyrinth.erosion_engine import get_erosion_engine
            erosion = get_erosion_engine()
            erosion_state = erosion.get_state(attacker_ip)

            # If confusion is high, accelerate erosion
            if state.confusion_score > 60 and erosion_state.confidence > 0.3:
                # Force a dead end to accelerate erosion
                dead_end = erosion.generate_dead_end(attacker_ip)
                self._log("INFO", f"Feeding erosion engine for {attacker_ip} — dead end served (confidence: {dead_end.get('_meta', {}).get('attacker_confidence_after', 0):.0%})")
                return {
                    "fed": True,
                    "erosion_confidence": dead_end.get("_meta", {}).get("attacker_confidence_after", 0),
                    "confusion_score": state.confusion_score,
                }

            return {"fed": False, "confusion_score": state.confusion_score, "erosion_confidence": erosion_state.confidence}
        except Exception as e:
            logger.debug("BRAINMAZE: Erosion engine integration failed: %s", e)
            return {"fed": False, "error": str(e)}

    # ── SSE FEED ─────────────────────────────────────────────────────

    async def subscribe_events(self):
        """Subscribe to real-time BrainMaze events. Yields dict events."""
        import asyncio
        queue = asyncio.Queue(maxsize=100)
        self._log_subscribers.append(queue)
        try:
            # Send recent log history
            for entry in self._system_log[-20:]:
                yield entry
            # Stream new events
            while True:
                entry = await queue.get()
                yield entry
        finally:
            if queue in self._log_subscribers:
                self._log_subscribers.remove(queue)

    def get_recent_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent system logs for REST polling."""
        return self._system_log[-limit:]

    # ── INTERNAL ─────────────────────────────────────────────────────

    def _record_technique(self, state: ConfusionState, technique: str, data: dict[str, Any]) -> None:
        """Record a technique deployment in the attacker's history."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "technique": technique,
            "confusion_score": state.confusion_score,
            "phase": state.phase.value,
            **data,
        }
        state.technique_history.append(entry)
        if len(state.technique_history) > 200:
            state.technique_history = state.technique_history[-200:]

    def _log(self, level: str, message: str, **extra) -> None:
        """Emit a system log event."""
        import asyncio
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            "source": "brainmaze",
            **extra,
        }
        self._system_log.append(entry)
        if len(self._system_log) > 500:
            self._system_log = self._system_log[-500:]
        # Broadcast to SSE subscribers
        for queue in self._log_subscribers:
            try:
                queue.put_nowait(entry)
            except asyncio.QueueFull:
                pass

        if level == "CRITICAL":
            logger.critical("BRAINMAZE: %s", message)
        elif level == "WARN":
            logger.warning("BRAINMAZE: %s", message)
        else:
            logger.info("BRAINMAZE: %s", message)


# ── Singleton ────────────────────────────────────────────────────────────

_orchestrator: Optional[BrainMazeOrchestrator] = None


def get_brainmaze_orchestrator() -> BrainMazeOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = BrainMazeOrchestrator()
    return _orchestrator