"""Epistemic Erosion Engine — systematically destroys attacker confidence.

This is the novel contribution of EPHEMERAL LABYRINTH. No paper has described
a system that deliberately degrades an attacker's epistemic confidence through
engineered dead ends, fake successes, and cognitive load.

The engine:
1. Tracks attacker confidence (starts at 1.0, erodes through dead ends)
2. Generates fake success responses (fake shells, fake data, fake credentials)
3. Engineers dead-end cascades (each "success" leads to another fake layer)
4. Occasionally mixes real-but-low-value assets to maintain belief
5. Monitors for the "confidence crisis" — when the attacker starts doubting
6. Accelerates erosion near the crisis point to push the attacker to give up

The cognitive model:
- Attackers operate on CONFIDENCE IN RECONNAISSANCE
- Each successful "exploit" INCREASES confidence → they trust the environment
- Each dead end after a success DECREASES confidence → was the success fake?
- After N dead ends, confidence crisis triggers
- System can detect the crisis by behavioral changes (retrying, scanning again,
  trying different tools, abandoning the engagement)

Academic basis (indirect — nobody has built this):
- Dykstra & Shortridge 2022: "Sludge for Good" — impose costs on attackers
- Kumar et al.: hypothesis-testing framework — each fake asset forces a hypothesis
- Polad et al. 2019: fake vulnerabilities cause "erroneous construction of attack path"
- Verification Cost Asymmetry (2025): cognitive warfare exploits verification costs
- Confirmation bias (Springer 2024): attackers' prior beliefs can be exploited
"""

from __future__ import annotations

import logging
import random
import secrets
random.seed(secrets.randbelow(2**32))
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from app.labyrinth.recon_detector import AttackerProfile, ThreatLevel, ReconType

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
#  EROSION STATE
# ═══════════════════════════════════════════════════════════════════════

class ErosionPhase(str, Enum):
    """The phases of epistemic erosion an attacker goes through."""
    UNAWARE = "unaware"        # Attacker hasn't triggered any deception yet
    ENGAGED = "engaged"        # Attacker is exploring the MirrorGraph
    CONFIDENT = "confident"   # Attacker has had "successes" — peak confidence
    DOUBT = "doubt"            # First dead ends — "something's off"
    CRISIS = "crisis"          # Confidence crisis — "is any of this real?"
    ABANDONMENT = "abandonment"  # Attacker is giving up


class FakeSuccessType(str, Enum):
    """Types of fake success responses the engine can generate."""
    FAKE_SHELL = "fake_shell"           # Simulated shell access
    FAKE_CRED = "fake_cred"            # Fake credentials that "work"
    FAKE_DATA = "fake_data"            # Fake data exfiltration
    FAKE_LATERAL = "fake_lateral"      # Fake lateral movement target
    FAKE_PRIVESC = "fake_privesc"      # Fake privilege escalation
    FAKE_TUNNEL = "fake_tunnel"        # Fake tunnel/proxy endpoint


@dataclass
class FakeInteraction:
    """A single fake interaction served to an attacker."""
    interaction_id: str
    attacker_ip: str
    success_type: FakeSuccessType
    timestamp: datetime
    details: dict[str, Any]
    confidence_before: float
    confidence_after: float
    will_lead_to_dead_end: bool = True
    dead_end_distance: int = 1  # how many steps until the dead end


@dataclass
class ErosionState:
    """Tracks the epistemic erosion progress for a single attacker."""
    attacker_ip: str
    phase: ErosionPhase = ErosionPhase.UNAWARE
    confidence: float = 1.0
    peak_confidence: float = 1.0
    fake_successes_served: int = 0
    dead_ends_served: int = 0
    interactions: list[FakeInteraction] = field(default_factory=list)
    crisis_detected: bool = False
    crisis_timestamp: Optional[datetime] = None
    abandonment_predicted: bool = False

    # Behavioral indicators of confidence crisis
    retry_events: int = 0          # attacker retrying same action
    tool_switch_events: int = 0   # attacker switching tools
    idle_periods: int = 0         # attacker going quiet (thinking)
    rescan_events: int = 0        # attacker re-scanning (doubting recon)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attacker_ip": self.attacker_ip,
            "phase": self.phase.value,
            "confidence": round(self.confidence, 3),
            "peak_confidence": round(self.peak_confidence, 3),
            "fake_successes_served": self.fake_successes_served,
            "dead_ends_served": self.dead_ends_served,
            "crisis_detected": self.crisis_detected,
            "crisis_timestamp": self.crisis_timestamp.isoformat() if self.crisis_timestamp else None,
            "abandonment_predicted": self.abandonment_predicted,
            "retry_events": self.retry_events,
            "tool_switch_events": self.tool_switch_events,
            "idle_periods": self.idle_periods,
            "rescan_events": self.rescan_events,
            "interactions_count": len(self.interactions),
        }


# ═══════════════════════════════════════════════════════════════════════
#  FAKE RESPONSE TEMPLATES
# ═══════════════════════════════════════════════════════════════════════

# Fake shell responses — what the attacker sees when they "exploit" something
FAKE_SHELL_RESPONSES = [
    {"service": "SSH", "response": "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\n\nLast login: {timestamp} from 10.0.1.42\nuser@web-server-01:~$ "},
    {"service": "Web Shell", "response": "Linux web-prod-02 5.15.0-89-generic #99-Ubuntu SMP Mon Sep 25 15:00:00 UTC 2023 x86_64\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\nwww-data@web-prod-02:/var/www/html$ "},
    {"service": "MySQL", "response": "Welcome to the MySQL monitor.  Commands end with ; or \\g.\nYour MySQL connection id is 8472\nServer version: 8.0.35 MySQL Community Server - GPL\n\nmysql> "},
    {"service": "Redis", "response": "REDIS 7.2.3 (00000000/0) 64 bit\nRunning in standalone mode\nredis 10.0.2.15:6379> "},
    {"service": "PostgreSQL", "response": "psql (15.4, server 15.4)\nType \"help\" for help.\n\npostgres=# "},
]

# Fake credential responses — what the attacker sees when they "find" creds
FAKE_CRED_RESPONSES = [
    {"type": "config_file", "content": "[database]\nhost = 10.0.2.15\nport = 5432\nuser = admin\npassword = Summer2024!Strong\ndbname = production\n"},
    {"type": "env_file", "content": "DB_PASSWORD=SuperSecret123!\nAPI_KEY=sk-proj-abc123def456ghi789\nJWT_SECRET=e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"},
    {"type": "bash_history", "content": "ssh -i ~/.ssh/id_rsa deploy@10.0.2.20\nmysql -u root -pS3cureP@ss! -h 10.0.2.15\nsudo su -\ncat /etc/shadow\n"},
    {"type": "git_credentials", "content": "https://admin:g1tHub_T0k3n_abc123@github.com/company/internal-tools.git\n"},
]

# Fake data — what the attacker sees when they "exfiltrate" data
FAKE_DATA_RESPONSES = [
    {"type": "user_database", "content": "id,username,email,password_hash,role\n1,admin,admin@lab.local,$2b$12$abc123...,superuser\n2,jdoe,jdoe@lab.local,$2b$12$def456...,user\n3,svc_account,svc@lab.local,$2b$12$ghi789...,service\n"},
    {"type": "api_keys", "content": "STRIPE_SECRET=sk_live_abc123def456\nSENDGRID_KEY=SG.abc123.def456\nSLACK_TOKEN=xoxb-abc123-def456\nTWILIO_TOKEN=SK1234567890abcdef\n"},
    {"type": "config_dump", "content": "[app]\nSECRET_KEY=development-key-change-in-production\nDEBUG=True\nALLOWED_HOSTS=*\nDATABASE_URL=postgresql://admin:S3cure@10.0.2.15:5432/prod\n"},
    {"type": "source_code", "content": "#!/usr/bin/env python3\nfrom flask import Flask\nimport os\n\napp = Flask(__name__)\napp.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key')\n\n@app.route('/api/v1/users')\ndef get_users():\n    # TODO: Add auth before deploying to prod\n    return User.query.all()\n"},
]


# ═══════════════════════════════════════════════════════════════════════
#  EPISTEMIC EROSION ENGINE
# ═══════════════════════════════════════════════════════════════════════

class EpistemicErosionEngine:
    """Systematically destroys attacker confidence through engineered dead ends.

    The engine operates in a cycle:
    1. SERVE a fake success (increases attacker confidence)
    2. WAIT for the attacker to follow the success deeper
    3. HIT them with a dead end (decreases confidence)
    4. Repeat with increasing complexity
    5. DETECT behavioral signs of confidence crisis
    6. If crisis detected, ACCELERATE erosion to push toward abandonment

    The key insight: a fake success that works perfectly is MORE damaging to
    the attacker's psychology than a blocked attack. Because now they TRUST
    the environment. And when that trust is violated, the doubt runs deeper
    than if they'd never succeeded at all.
    """

    def __init__(self) -> None:
        self._states: dict[str, ErosionState] = {}

    # ── STATE MANAGEMENT ───────────────────────────────────────────────

    def get_state(self, attacker_ip: str) -> ErosionState:
        """Get or create the erosion state for an attacker."""
        if attacker_ip not in self._states:
            self._states[attacker_ip] = ErosionState(attacker_ip=attacker_ip)
        return self._states[attacker_ip]

    def get_all_states(self) -> list[ErosionState]:
        return list(self._states.values())

    # ── FAKE SUCCESS GENERATION ───────────────────────────────────────

    def generate_fake_success(
        self,
        attacker_ip: str,
        success_type: Optional[FakeSuccessType] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> FakeInteraction:
        """Generate a fake success response for the attacker.

        The response should be:
        - Plausible (consistent with the MirrorGraph)
        - Rewarding (makes the attacker feel they're making progress)
        - Trapped (will eventually lead to a dead end)
        - Escalating (each success is slightly more complex than the last)
        """
        state = self.get_state(attacker_ip)
        confidence_before = state.confidence

        # Pick success type if not specified
        if not success_type:
            success_type = self._select_success_type(state)

        # Generate the response
        response = self._generate_response(success_type, context)

        # Increase confidence (the attacker feels rewarded)
        confidence_boost = min(0.1, 0.03 + 0.01 * state.fake_successes_served)
        state.confidence = min(1.0, state.confidence + confidence_boost)
        state.peak_confidence = max(state.peak_confidence, state.confidence)
        state.fake_successes_served += 1

        # Transition phases
        if state.phase == ErosionPhase.UNAWARE:
            state.phase = ErosionPhase.ENGAGED
        elif state.phase == ErosionPhase.ENGAGED and state.fake_successes_served >= 2:
            state.phase = ErosionPhase.CONFIDENT
        elif state.phase == ErosionPhase.DOUBT:
            # After a success during doubt, they re-engage
            state.phase = ErosionPhase.CONFIDENT

        interaction = FakeInteraction(
            interaction_id=f"fx_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{state.fake_successes_served}",
            attacker_ip=attacker_ip,
            success_type=success_type,
            timestamp=datetime.now(timezone.utc),
            details=response,
            confidence_before=confidence_before,
            confidence_after=state.confidence,
            will_lead_to_dead_end=True,
            dead_end_distance=random.randint(1, 3),
        )

        state.interactions.append(interaction)

        logger.info(
            "EPHEMERAL LABYRINTH: Served fake success #%d to %s — type=%s, "
            "confidence %.0f%% → %.0f%% (phase: %s)",
            state.fake_successes_served, attacker_ip, success_type.value,
            confidence_before * 100, state.confidence * 100, state.phase.value,
        )

        return interaction

    def generate_dead_end(
        self,
        attacker_ip: str,
        context: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Generate a dead end response — the attacker followed a fake path to nowhere.

        This is where confidence erodes. The dead end should:
        - Feel like a natural consequence of the previous "success"
        - Not be obviously a trap (no "ACCESS DENIED" — that reveals defense)
        - Instead show: empty data, broken pipe, connection reset, nothing useful
        """
        state = self.get_state(attacker_ip)
        confidence_before = state.confidence

        # Erode confidence — the amount depends on the phase
        if state.phase == ErosionPhase.CONFIDENT:
            erosion = 0.08  # first dead ends hit hardest
        elif state.phase == ErosionPhase.DOUBT:
            erosion = 0.12  # during doubt, each dead end is more damaging
        elif state.phase == ErosionPhase.CRISIS:
            erosion = 0.20  # during crisis, every dead end pushes toward abandonment
        else:
            erosion = 0.05

        state.confidence = max(0.0, state.confidence - erosion)
        state.dead_ends_served += 1

        # Phase transitions
        if state.confidence < 0.6 and state.phase == ErosionPhase.CONFIDENT:
            state.phase = ErosionPhase.DOUBT
            logger.warning(
                "EPHEMERAL LABYRINTH: %s entered DOUBT phase (confidence: %.0f%%, dead ends: %d)",
                attacker_ip, state.confidence * 100, state.dead_ends_served,
            )
        elif state.confidence < 0.3 and state.phase == ErosionPhase.DOUBT:
            state.phase = ErosionPhase.CRISIS
            state.crisis_detected = True
            state.crisis_timestamp = datetime.now(timezone.utc)
            logger.warning(
                "EPHEMERAL LABYRINTH: ⚡ CONFIDENCE CRISIS detected for %s "
                "(confidence: %.0f%%, dead ends: %d, fake successes: %d)",
                attacker_ip, state.confidence * 100, state.dead_ends_served,
                state.fake_successes_served,
            )
        elif state.confidence < 0.1 and state.phase == ErosionPhase.CRISIS:
            state.phase = ErosionPhase.ABANDONMENT
            state.abandonment_predicted = True
            logger.warning(
                "EPHEMERAL LABYRINTH: %s predicted to ABANDON engagement "
                "(confidence: %.0f%%, dead ends: %d)",
                attacker_ip, state.confidence * 100, state.dead_ends_served,
            )

        # Generate dead end response
        dead_end_type = random.choice([
            "empty_result",
            "connection_reset",
            "permission_denied_real",
            "broken_pipe",
            "service_unavailable",
            "null_data",
        ])

        dead_end_responses = {
            "empty_result": {"status": "success", "data": [], "message": "Query returned 0 rows"},
            "connection_reset": {"error": "Connection reset by peer", "errno": 104},
            "permission_denied_real": {"error": "Permission denied (publickey)", "exit_code": 255},
            "broken_pipe": {"error": "Broken pipe", "errno": 32},
            "service_unavailable": {"status": 503, "error": "Service Unavailable", "detail": "The service is temporarily unavailable"},
            "null_data": {"status": "success", "data": None, "message": "No data found in this table"},
        }

        response = dead_end_responses.get(dead_end_type, dead_end_responses["empty_result"])
        response["_meta"] = {
            "attacker_confidence_before": round(confidence_before, 3),
            "attacker_confidence_after": round(state.confidence, 3),
            "erosion_amount": round(erosion, 3),
            "dead_end_number": state.dead_ends_served,
            "phase": state.phase.value,
        }

        logger.info(
            "EPHEMERAL LABYRINTH: Served dead end #%d to %s — type=%s, "
            "confidence %.0f%% → %.0f%% (phase: %s)",
            state.dead_ends_served, attacker_ip, dead_end_type,
            confidence_before * 100, state.confidence * 100, state.phase.value,
        )

        return response

    # ── BEHAVIORAL ANALYSIS ───────────────────────────────────────────

    def process_behavior(self, attacker_ip: str, behavior_type: str) -> Optional[ErosionPhase]:
        """Process behavioral indicators that the attacker is losing confidence.

        behavior_type can be:
        - "retry": attacker retrying a failed action
        - "tool_switch": attacker switching to a different tool
        - "idle": attacker going quiet for an extended period
        - "rescan": attacker re-scanning a target they already scanned
        - "abandon": attacker appears to be leaving

        Returns the new phase if it changed, None otherwise.
        """
        state = self.get_state(attacker_ip)
        old_phase = state.phase

        if behavior_type == "retry":
            state.retry_events += 1
            if state.phase in (ErosionPhase.DOUBT, ErosionPhase.CRISIS):
                state.confidence = max(0.0, state.confidence - 0.03)
        elif behavior_type == "tool_switch":
            state.tool_switch_events += 1
            if state.phase in (ErosionPhase.CONFIDENT, ErosionPhase.DOUBT):
                state.confidence = max(0.0, state.confidence - 0.05)
        elif behavior_type == "idle":
            state.idle_periods += 1
            if state.idle_periods >= 3 and state.phase == ErosionPhase.CONFIDENT:
                state.phase = ErosionPhase.DOUBT
                logger.info("EPHEMERAL LABYRINTH: %s entered DOUBT (idle behavior)", attacker_ip)
        elif behavior_type == "rescan":
            state.rescan_events += 1
            if state.phase == ErosionPhase.DOUBT:
                state.phase = ErosionPhase.CRISIS
                state.crisis_detected = True
                state.crisis_timestamp = datetime.now(timezone.utc)
                logger.warning(
                    "EPHEMERAL LABYRINTH: ⚡ CONFIDENCE CRISIS for %s "
                    "(re-scanning — they don't trust their recon)",
                    attacker_ip,
                )
        elif behavior_type == "abandon":
            state.phase = ErosionPhase.ABANDONMENT
            state.abandonment_predicted = True
            logger.info("EPHEMERAL LABYRINTH: %s appears to be ABANDONING the engagement", attacker_ip)

        return state.phase if state.phase != old_phase else None

    # ── STRATEGY ──────────────────────────────────────────────────────

    def get_next_action(self, attacker_ip: str) -> str:
        """Determine what the system should serve to the attacker next.

        Strategy:
        - UNAWARE: wait for engagement
        - ENGAGED: serve 1-2 fake successes to build confidence
        - CONFIDENT: alternate successes and dead ends (success ratio ~70%)
        - DOUBT: serve more dead ends (success ratio ~30%)
        - CRISIS: accelerate dead ends, no more successes (push toward abandonment)
        - ABANDONMENT: log the engagement, prepare post-incident analysis
        """
        state = self.get_state(attacker_ip)

        if state.phase == ErosionPhase.UNAWARE:
            return "wait"
        elif state.phase == ErosionPhase.ENGAGED:
            return "fake_success"
        elif state.phase == ErosionPhase.CONFIDENT:
            return "fake_success" if random.random() < 0.7 else "dead_end"
        elif state.phase == ErosionPhase.DOUBT:
            return "fake_success" if random.random() < 0.3 else "dead_end"
        elif state.phase == ErosionPhase.CRISIS:
            return "dead_end"
        elif state.phase == ErosionPhase.ABANDONMENT:
            return "log_and_analyze"

        return "wait"

    # ── RESPONSE GENERATION ───────────────────────────────────────────

    def _select_success_type(self, state: ErosionState) -> FakeSuccessType:
        """Select the next fake success type based on progression."""
        if state.fake_successes_served < 2:
            return random.choice([FakeSuccessType.FAKE_SHELL, FakeSuccessType.FAKE_CRED])
        elif state.fake_successes_served < 5:
            return random.choice([
                FakeSuccessType.FAKE_SHELL, FakeSuccessType.FAKE_CRED,
                FakeSuccessType.FAKE_DATA, FakeSuccessType.FAKE_LATERAL,
            ])
        else:
            return random.choice([
                FakeSuccessType.FAKE_DATA, FakeSuccessType.FAKE_LATERAL,
                FakeSuccessType.FAKE_PRIVESC, FakeSuccessType.FAKE_TUNNEL,
            ])

    def _generate_response(self, success_type: FakeSuccessType, context: Optional[dict]) -> dict[str, Any]:
        """Generate a fake success response."""
        if success_type == FakeSuccessType.FAKE_SHELL:
            template = random.choice(FAKE_SHELL_RESPONSES)
            timestamp = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
            return {
                "type": "shell_access",
                "service": template["service"],
                "output": template["response"].format(timestamp=timestamp),
                "appears_real": True,
            }
        elif success_type == FakeSuccessType.FAKE_CRED:
            template = random.choice(FAKE_CRED_RESPONSES)
            return {
                "type": "credential_discovery",
                "source": template["type"],
                "content": template["content"],
                "appears_real": True,
            }
        elif success_type == FakeSuccessType.FAKE_DATA:
            template = random.choice(FAKE_DATA_RESPONSES)
            return {
                "type": "data_exfiltration",
                "data_type": template["type"],
                "content": template["content"],
                "appears_real": True,
            }
        elif success_type == FakeSuccessType.FAKE_LATERAL:
            return {
                "type": "lateral_movement",
                "target_host": f"10.0.2.{random.randint(10, 50)}",
                "target_name": random.choice(["web-prod-02", "db-slave-01", "app-worker-03", "jenkins-agent-01"]),
                "access_method": random.choice(["ssh_key", "password_reuse", "kerberos_ticket"]),
                "appears_real": True,
            }
        elif success_type == FakeSuccessType.FAKE_PRIVESC:
            return {
                "type": "privilege_escalation",
                "method": random.choice(["sudo_misconfiguration", "suid_binary", "kernel_exploit", "cron_job"]),
                "new_uid": 0,
                "new_user": "root",
                "appears_real": True,
            }
        elif success_type == FakeSuccessType.FAKE_TUNNEL:
            return {
                "type": "tunnel_established",
                "protocol": random.choice(["SSH", "DNS", "ICMP", "HTTPS"]),
                "local_port": random.randint(8000, 9999),
                "remote_port": random.choice([22, 443, 8080]),
                "appears_real": True,
            }
        return {"type": "unknown", "appears_real": False}


# ── Singleton ────────────────────────────────────────────────────────────

_engine: Optional[EpistemicErosionEngine] = None


def get_erosion_engine() -> EpistemicErosionEngine:
    global _engine
    if _engine is None:
        _engine = EpistemicErosionEngine()
    return _engine