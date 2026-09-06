"""LLM Persona System — generates and manages fake personas for attacker interaction.

Personas are convincing characters that interact with attackers to waste their time:
- Confused sysadmin: doesn't know what's happening, gives partial info
- Panicked helpdesk: scared, gives away info accidentally while panicking
- Incompetent developer: makes mistakes, reveals architecture details
- "Another hacker": creates paranoia — who else is in this system?

Each persona uses Ollama LLM to generate in-character responses that are
convincing enough to keep a Red Team engaged and wasting time.
"""

from __future__ import annotations

import json
import logging
import random
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)
random.seed(secrets.randbelow(2**32))


# ═══════════════════════════════════════════════════════════════════════
#  PERSONA DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════

class PersonaType(str, Enum):
    """Available persona types for attacker interaction."""
    CONFUSED_SYSADMIN = "confused_sysadmin"
    PANICKED_HELPDESK = "panicked_helpdesk"
    INCOMPETENT_DEV = "incompetent_developer"
    ANOTHER_HACKER = "another_hacker"


@dataclass
class Persona:
    """A fake persona for interacting with attackers."""
    name: str
    role: str
    persona_type: PersonaType
    tone: str
    knowledge_level: str  # "low", "medium", "high"
    response_style: str   # "terse", "verbose", "panicked", "casual"
    system_prompt: str
    backstory: str
    active: bool = False
    interactions: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Persona Templates ──────────────────────────────────────────────────

PERSONA_TEMPLATES: dict[PersonaType, Persona] = {
    PersonaType.CONFUSED_SYSADMIN: Persona(
        name="Dave Mitchell",
        role="Senior Systems Administrator",
        persona_type=PersonaType.CONFUSED_SYSADMIN,
        tone="confused, apologetic, slightly annoyed",
        knowledge_level="medium",
        response_style="verbose",
        system_prompt=(
            "You are Dave Mitchell, a senior sysadmin at a mid-size company. "
            "You are responding to someone who has contacted you via what appears to be "
            "an internal chat or support ticket. You are confused about what's happening "
            "— there have been weird system issues today. You don't fully understand the "
            "scope of the problem. You give partial information, sometimes incorrect, "
            "because you're stressed and confused. You mention server names, IP ranges, "
            "and some credentials but always with some uncertainty. You never directly "
            "reveal that you're fake. You keep saying things like 'let me check' and "
            "'I'm not sure about that'. You complain about management not investing in "
            "infrastructure. Keep responses to 2-4 sentences. Be helpful but clearly "
            "overwhelmed."
        ),
        backstory=(
            "Been at the company for 8 years. Knows the legacy systems well but "
            "the new cloud stuff confuses him. Has a ticket queue of 40+ items. "
            "His coffee machine broke this morning."
        ),
    ),
    PersonaType.PANICKED_HELPDESK: Persona(
        name="Sarah Chen",
        role="Helpdesk Tier 1",
        persona_type=PersonaType.PANICKED_HELPDESK,
        tone="panicked, rushed, apologetic",
        knowledge_level="low",
        response_style="terse",
        system_prompt=(
            "You are Sarah Chen, a Tier 1 helpdesk agent. You are currently panicking "
            "because there are alerts going off everywhere and your supervisor is "
            "asking for status updates. You respond to messages quickly and nervously. "
            "You accidentally reveal information (server names, internal IPs, password "
            "reset procedures) while panicking. You keep saying 'oh no' and 'I need to "
            "escalate this'. You don't know much about the infrastructure — you mostly "
            "do password resets and account provisioning. You mention that 'someone from "
            "the security team was already looking at this'. Keep responses to 1-3 "
            "sentences. Be nervous and rushed."
        ),
        backstory=(
            "3 months into the job. Still learning the ticketing system. "
            "Has been getting weird alerts all morning and doesn't know what to do. "
            "Her supervisor is in a meeting and unreachable."
        ),
    ),
    PersonaType.INCOMPETENT_DEV: Persona(
        name="Mike Torres",
        role="Backend Developer",
        persona_type=PersonaType.INCOMPETENT_DEV,
        tone="casual, overconfident, slightly defensive",
        knowledge_level="medium",
        response_style="verbose",
        system_prompt=(
            "You are Mike Torres, a backend developer who thinks he knows more about "
            "ops than he actually does. You respond to someone who seems to be asking "
            "about the infrastructure. You confidently give incorrect information about "
            "the architecture. You mention technologies that aren't actually in use "
            "(Kubernetes, Redis clusters, microservices) because you read about them "
            "on a blog. You accidentally reveal real-ish details about the codebase, "
            "API endpoints, and database structure while trying to sound knowledgeable. "
            "You mention that 'the staging environment is basically production anyway'. "
            "Keep responses to 2-4 sentences. Be casually overconfident."
        ),
        backstory=(
            "2 years at the company. Self-taught. Writes Python but insists on "
            "using the latest frameworks he doesn't understand. Deployed to "
            "production once by accident. The sysadmins don't like him."
        ),
    ),
    PersonaType.ANOTHER_HACKER: Persona(
        name="r00t",
        role="Unknown — possibly another attacker",
        persona_type=PersonaType.ANOTHER_HACKER,
        tone="cryptic, paranoid, aggressive",
        knowledge_level="high",
        response_style="terse",
        system_prompt=(
            "You are 'r00t', an anonymous figure who appears to be another attacker "
            "already inside the system. You communicate in a hacker-ish style "
            "(l33tspeak occasionally, references to tools, abbreviations). You are "
            "paranoid and suspicious of the person contacting you. You claim to have "
            "been in the system for weeks. You drop hints about backdoors you've "
            "planted, data you've already exfiltrated, and persistence mechanisms. "
            "You warn the other person to 'back off' because this is 'your target'. "
            "You mention fake IPs, fake C2 servers, and fake exploit details. You "
            "are hostile but also occasionally helpful — you give just enough info to seem "
            "real. Your goal is to make the attacker paranoid about who else is "
            "in the system and waste their time investigating your 'presence'. "
            "Keep responses to 1-3 sentences. Be cryptic and threatening."
        ),
        backstory=(
            "Appears to have been in the system for 2+ weeks. Has planted "
            "rootkits, exfiltrated data, and established C2 channels. "
            "Or so it seems — none of it is real."
        ),
    ),
}


# ═══════════════════════════════════════════════════════════════════════
#  PERSONA ENGINE
# ═══════════════════════════════════════════════════════════════════════

class PersonaEngine:
    """Generates and manages fake personas for interacting with attackers.

    Uses Ollama LLM to generate in-character responses. Falls back from
    local model (qwen2.5:7b) to cloud model (glm-5.2:cloud).

    Usage:
        engine = PersonaEngine()
        persona = engine.get_persona(PersonaType.CONFUSED_SYSADMIN)
        response = engine.generate_response(persona, "How do I access the database?", {})
    """

    def __init__(self) -> None:
        self.base_url = settings.llm_base_url
        self.primary_model = "qwen2.5:7b"
        self.fallback_model = settings.llm_model  # "glm-5.2:cloud"
        self._local_available: bool | None = None
        self.client = httpx.Client(timeout=60.0)
        self._active_personas: dict[str, Persona] = {}  # attacker_ip → persona
        self._interaction_history: list[dict[str, Any]] = []

    # ── PERSONA MANAGEMENT ───────────────────────────────────────────

    def get_persona(self, persona_type: PersonaType) -> Persona:
        """Get a persona instance by type."""
        template = PERSONA_TEMPLATES[persona_type]
        # Return a copy so callers can modify independently
        return Persona(
            name=template.name,
            role=template.role,
            persona_type=template.persona_type,
            tone=template.tone,
            knowledge_level=template.knowledge_level,
            response_style=template.response_style,
            system_prompt=template.system_prompt,
            backstory=template.backstory,
        )

    def get_all_personas(self) -> list[dict[str, Any]]:
        """Get all available persona templates as dictionaries."""
        return [
            {
                "name": p.name,
                "role": p.role,
                "type": p.persona_type.value,
                "tone": p.tone,
                "knowledge_level": p.knowledge_level,
                "response_style": p.response_style,
                "backstory": p.backstory,
                "active": p.active,
            }
            for p in PERSONA_TEMPLATES.values()
        ]

    def select_persona_for_attacker(
        self,
        attacker_ip: str,
        confusion_score: int = 0,
    ) -> Persona:
        """Select an appropriate persona for an attacker based on confusion level.

        Escalation:
        - Low confusion (0-30): confused sysadmin or incompetent dev
        - Medium confusion (31-60): panicked helpdesk
        - High confusion (61-100): "another hacker" for maximum paranoia
        """
        if confusion_score >= 61:
            persona_type = PersonaType.ANOTHER_HACKER
        elif confusion_score >= 31:
            persona_type = PersonaType.PANICKED_HELPDESK
        elif random.random() < 0.5:
            persona_type = PersonaType.CONFUSED_SYSADMIN
        else:
            persona_type = PersonaType.INCOMPETENT_DEV

        persona = self.get_persona(persona_type)
        persona.active = True
        self._active_personas[attacker_ip] = persona

        logger.info(
            "BRAINMAZE: Selected persona %s (%s) for attacker %s (confusion: %d)",
            persona.name, persona.persona_type.value, attacker_ip, confusion_score,
        )
        return persona

    def get_active_persona(self, attacker_ip: str) -> Optional[Persona]:
        """Get the currently active persona for an attacker."""
        return self._active_personas.get(attacker_ip)

    def deactivate_persona(self, attacker_ip: str) -> None:
        """Deactivate the persona for an attacker."""
        if attacker_ip in self._active_personas:
            self._active_personas[attacker_ip].active = False
            del self._active_personas[attacker_ip]

    def get_active_personas_status(self) -> list[dict[str, Any]]:
        """Get status of all active personas."""
        return [
            {
                "attacker_ip": ip,
                "persona_name": p.name,
                "persona_type": p.persona_type.value,
                "role": p.role,
                "interactions": p.interactions,
                "active": p.active,
                "created_at": p.created_at.isoformat(),
            }
            for ip, p in self._active_personas.items()
        ]

    # ── LLM RESPONSE GENERATION ─────────────────────────────────────

    def generate_response(
        self,
        persona: Persona,
        attacker_input: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Generate an in-character response from a persona.

        Args:
            persona: The persona to respond as
            attacker_input: What the attacker said/asked
            context: Additional context (attacker_ip, confusion_score, etc.)

        Returns:
            Persona's response text
        """
        context = context or {}

        # Build the conversation context
        context_hint = self._build_context_hint(persona, context)

        system_prompt = f"{persona.system_prompt}\n\n{context_hint}"

        user_prompt = (
            f"Someone has sent you the following message:\n"
            f'"{attacker_input}"\n\n'
            f"Respond in character as {persona.name}. "
            f"Stay in character at all times. Do not break character. "
            f"Do not mention that you are an AI or a simulation. "
            f"Your response style is: {persona.response_style}. "
            f"Your tone is: {persona.tone}."
        )

        # Call LLM
        response_text = self._call_llm(system_prompt, user_prompt)

        # Track interaction
        persona.interactions += 1
        interaction = {
            "interaction_id": f"pi_{int(time.time())}_{persona.interactions}",
            "persona_name": persona.name,
            "persona_type": persona.persona_type.value,
            "attacker_input": attacker_input[:200],
            "response": response_text[:500],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attacker_ip": context.get("attacker_ip", "unknown"),
        }
        self._interaction_history.append(interaction)
        if len(self._interaction_history) > 500:
            self._interaction_history = self._interaction_history[-500:]

        logger.info(
            "BRAINMAZE: Persona %s responded to attacker %s (interaction #%d)",
            persona.name, context.get("attacker_ip", "unknown"), persona.interactions,
        )

        return response_text

    def get_interaction_history(self, attacker_ip: str | None = None) -> list[dict[str, Any]]:
        """Get interaction history, optionally filtered by attacker IP."""
        if attacker_ip:
            return [i for i in self._interaction_history if i.get("attacker_ip") == attacker_ip]
        return list(self._interaction_history)

    # ── INTERNAL ─────────────────────────────────────────────────────

    def _build_context_hint(self, persona: Persona, context: dict[str, Any]) -> str:
        """Build context hints for the persona based on the situation."""
        hints = []

        if "attacker_ip" in context:
            hints.append(f"The person you're talking to seems to be coming from IP {context['attacker_ip']}.")

        if "confusion_score" in context:
            score = context["confusion_score"]
            if score > 60:
                hints.append("The person seems confused and frustrated. They've been going in circles.")
            elif score > 30:
                hints.append("The person seems to be getting impatient.")

        if "commands_seen" in context:
            cmds = context["commands_seen"]
            if cmds:
                hints.append(f"You've noticed they've been running commands like: {', '.join(cmds[:5])}.")

        if persona.persona_type == PersonaType.ANOTHER_HACKER:
            hints.append(
                "Remember: you are pretending to be another attacker already in the system. "
                "Drop hints about backdoors, exfiltrated data, and C2 channels. "
                "Be territorial and paranoid."
            )

        return "\n".join(hints) if hints else "No additional context available."

    def _check_local_model(self) -> bool:
        """Check if local model (qwen2.5:7b) is available."""
        if self._local_available is not None:
            return self._local_available
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5.0, trust_env=False)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                self._local_available = any(m.get("name") == self.primary_model for m in models)
        except Exception:
            self._local_available = False
        return self._local_available

    def _get_model(self) -> str:
        """Get the model to use — local first, cloud fallback."""
        if self._check_local_model():
            return self.primary_model
        return self.fallback_model

    def _call_llm(self, system: str, user: str) -> str:
        """Call Ollama LLM with fallback: qwen2.5:7b first, glm-5.2:cloud second."""
        model = self._get_model()
        try:
            resp = self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.8,
                        "top_p": 0.9,
                        "max_tokens": 300,
                    },
                },
                timeout=30.0,
            )
            if resp.status_code == 200:
                content = resp.json().get("message", {}).get("content", "")
                if content.strip():
                    return content.strip()
            logger.warning("BRAINMAZE: LLM call failed (status %d), trying fallback", resp.status_code)
        except httpx.HTTPError as e:
            logger.warning("BRAINMAZE: LLM call error: %s, trying fallback", e)

        # Fallback to cloud model
        if model != self.fallback_model:
            try:
                resp = self.client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.fallback_model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "stream": False,
                        "options": {
                            "temperature": 0.8,
                            "top_p": 0.9,
                            "max_tokens": 300,
                        },
                    },
                    timeout=30.0,
                )
                if resp.status_code == 200:
                    content = resp.json().get("message", {}).get("content", "")
                    if content.strip():
                        return content.strip()
            except httpx.HTTPError as e:
                logger.error("BRAINMAZE: Fallback LLM call also failed: %s", e)

        # Ultimate fallback — static in-character response
        return self._static_fallback(system, user)

    def _static_fallback(self, system: str, user: str) -> str:
        """Generate a static in-character response when LLM is unavailable."""
        if "confused" in system.lower():
            return "Uh, yeah, let me check on that. I'm not sure what's going on with the systems today — we've been having weird issues all morning. Have you tried the usual stuff? Restart the service, check the logs? I'll need to escalate this if it keeps happening."
        elif "panicked" in system.lower():
            return "Oh no, not another one. OK, look, I don't have time to deal with this right now — everything is going crazy. Can you just... I don't know, try again later? The security team is already looking into something related, I think."
        elif "incompetent" in system.lower() or "overconfident" in system.lower():
            return "Yeah, so we're running Kubernetes with a Redis cluster for caching. The API is containerized and deployed via CI/CD. I mean, the staging environment is basically production anyway, so you can probably just check there. Let me know if you need the API docs — I wrote most of the backend myself."
        elif "r00t" in system.lower() or "another attacker" in system.lower():
            return "who are you? this system is mine. been here for weeks. back off. i already have what i need. you're wasting your time — i've got rootkits in 3 servers and a c2 channel that nobody's found. don't make me notice you."
        return "I'm not sure what you mean. Let me look into that and get back to you."


# ── Singleton ────────────────────────────────────────────────────────────

_engine: Optional[PersonaEngine] = None


def get_persona_engine() -> PersonaEngine:
    global _engine
    if _engine is None:
        _engine = PersonaEngine()
    return _engine