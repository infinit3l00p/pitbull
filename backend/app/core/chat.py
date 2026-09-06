"""PITBULL Chat Interface — talk to PITBULL through the dashboard.

Uses the LLM reasoning engine with full PITBULL personality, memory, and context.
PITBULL responds in character with access to its exploration history.

Academic basis:
- PersonaAgent (ACL 2026): personality-driven agent interaction
- Browsing Like Human (ACL 2025): dual-process interaction mode
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from app.config import settings
from app.api.personality import _load_state
from app.core.database import cypher_read

logger = logging.getLogger(__name__)

CHAT_HISTORY_FILE = Path(settings.state_dir) / "chat_history.jsonl"


class ChatEngine:
    """Chat interface for talking to PITBULL."""

    def __init__(self):
        self.base_url = settings.llm_base_url
        # LOCAL ONLY — no cloud models, everything stays on this machine
        self.model = "qwen2.5:7b"
        self.client = httpx.AsyncClient(timeout=180.0, trust_env=False)  # async — won't block event loop

    def _build_system_prompt(self) -> str:
        """Build system prompt with PITBULL's current state."""
        state = _load_state()

        # Get recent memories for context (reduced for local model performance)
        memories = cypher_read(
            "MATCH (m:Memory {memory_type: 'episodic'}) "
            "RETURN m.content AS content, m.target AS target "
            "ORDER BY m.timestamp DESC LIMIT 5",
        )

        # Get semantic rules (top 3 only)
        rules = cypher_read(
            "MATCH (m:Memory {memory_type: 'semantic'}) "
            "RETURN m.subject AS subject, m.content AS content "
            "ORDER BY m.confidence DESC LIMIT 3",
        )

        recent_missions = [f"- {m.get('content', '')[:60]}" for m in memories if m.get("content")][:3]
        known_rules = [f"- {r.get('subject', '')}: {r.get('content', '')[:50]}" for r in rules if r.get("content")][:2]

        return f"""You are PITBULL, an autonomous digital explorer with personality. You map hidden internet infrastructure.
Personality: O={state.openness:.2f} C={state.conscientiousness:.2f} E={state.extraversion:.2f} A={state.agreeableness:.2f} N={state.neuroticism:.2f}
Mood: {state.mood} | Missions: {state.missions_completed} | Findings: {state.findings_total}
Recent: {chr(10).join(recent_missions) if recent_missions else 'None'}
Rules: {chr(10).join(known_rules) if known_rules else 'None'}
Speak as PITBULL — an entity with opinions. Be concise, real, and in character. Respond in plain text."""

    async def chat(self, message: str) -> dict[str, Any]:
        """Send a message to PITBULL and get a response."""
        chat_id = str(uuid.uuid4())[:12]
        timestamp = datetime.now().isoformat()

        # Build system prompt
        system_prompt = self._build_system_prompt()

        # Get recent chat context (last 10 messages)
        history = self._get_history(10)
        messages = [{"role": "system", "content": system_prompt}]
        messages.extend(history)
        messages.append({"role": "user", "content": message})

        try:
            resp = await self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": 0.7, "top_p": 0.9},
                },
            )
            resp.raise_for_status()
            reply = resp.json()["message"]["content"]

            # Save to history
            self._save_message("user", message, chat_id, timestamp)
            self._save_message("assistant", reply, chat_id, datetime.now().isoformat())

            return {
                "id": chat_id,
                "message": message,
                "reply": reply,
                "timestamp": timestamp,
                "personality": {
                    "openness": _load_state().openness,
                    "mood": _load_state().mood,
                    "missions": _load_state().missions_completed,
                },
            }

        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return {
                "id": chat_id,
                "message": message,
                "reply": f"I encountered an error processing your message: {e}",
                "timestamp": timestamp,
                "error": True,
            }

    def _save_message(self, role: str, content: str, chat_id: str, timestamp: str) -> None:
        """Save a message to chat history."""
        CHAT_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CHAT_HISTORY_FILE, "a") as f:
            f.write(json.dumps({
                "id": chat_id,
                "role": role,
                "content": content,
                "timestamp": timestamp,
            }) + "\n")

    def _get_history(self, limit: int = 10) -> list[dict[str, str]]:
        """Get recent chat history for context."""
        if not CHAT_HISTORY_FILE.exists():
            return []
        entries = []
        with open(CHAT_HISTORY_FILE, "r") as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue

        recent = entries[-limit * 2:]  # user + assistant
        return [{"role": e["role"], "content": e["content"]} for e in recent]

    def get_chat_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get full chat history for display."""
        if not CHAT_HISTORY_FILE.exists():
            return []
        entries = []
        with open(CHAT_HISTORY_FILE, "r") as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return entries[-limit:]


chat_engine = ChatEngine()