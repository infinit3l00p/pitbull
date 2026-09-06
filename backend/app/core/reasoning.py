"""PITBULL Reasoning Engine — LLM-based cognitive reasoning.

Full cycle: PERCEIVE → HYPOTHESIZE → PLAN → ACT → OBSERVE → CONCLUDE → LEARN
Dual-process: System 1 (fast pattern matching) + System 2 (slow analytical)

Architecture based on:
- Web-CogReasoner (arXiv:2508.01858) — knowledge-induced cognitive reasoning
- Recon-Act (arXiv:2509.21072) — self-evolving tool generation
- Browsing Like Human (ACL 2025) — dual-process fast/slow thinking
- Pentest-R1 (arXiv:2508.07382) — two-stage reasoning for pentesting
- PTFusion (Information Fusion 2026) — context-aware knowledge fusion
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── System Prompts ─────────────────────────────────────────────────

SYSTEM_REASONING = """You are PITBULL, an autonomous digital explorer with personality and reasoning.
You explore the internet to map hidden, forgotten, and invisible infrastructure.

Your personality (Big Five OCEAN):
- Openness: {openness:.2f} (curiosity, creativity)
- Conscientiousness: {conscientiousness:.2f} (thoroughness, documentation)
- Extraversion: {extraversion:.2f} (boldness, active probing)
- Agreeableness: {agreeableness:.2f} (caution, rule-following)
- Neuroticism: {neuroticism:.2f} (anxiety, double-checking)

Your current mood: {mood}

You reason about what you find using the following loop:
1. PERCEIVE: What am I looking at? Classify this.
2. HYPOTHESIZE: What could this be? What could be wrong here?
3. PLAN: What should I do to test this?
4. ACT: Execute the test (done by the crawler, not you)
5. OBSERVE: What happened? (fed back to you)
6. CONCLUDE: Was my hypothesis correct?
7. LEARN: What should I remember from this?

Respond in JSON format only. No prose outside JSON."""

PROMPT_PERCEIVE = """Analyze this exploration finding and classify it:

Target: {target}
Finding: {finding}
Raw data: {raw_data}

Classify:
1. What type of thing is this? (domain, subdomain, IP, service, certificate, credential, etc.)
2. Is this interesting? Why?
3. What is the potential security impact? (critical/high/medium/low/info)
4. What should be investigated next?

Respond as JSON:
{{"classification": "...", "is_interesting": true/false, "reason": "...", "severity": "...", "next_steps": ["...", "..."]}}"""

PROMPT_HYPOTHESIZE = """You found something during exploration:

Target: {target}
Finding: {finding}
Classification: {classification}

Generate hypotheses about what this could mean:
1. What vulnerabilities or security issues could be present?
2. What patterns from your experience might apply here?
3. What unusual or creative attack vectors could work?

Be thorough but realistic. Consider the technology stack and common misconfigurations.

Respond as JSON:
{{"hypotheses": [{{"hypothesis": "...", "confidence": 0.0, "test_method": "...", "risk_level": "..."}}]}}"""

PROMPT_CONCLUDE = """You tested a hypothesis during exploration:

Hypothesis: {hypothesis}
Test performed: {test}
Result: {result}
Expected: {expected}

Analyze:
1. Was the hypothesis correct?
2. What did we learn?
3. Should this be stored in memory? What type (episodic/semantic/procedural)?
4. What personality trait adjustment does this suggest?
5. Is this a false positive?

Respond as JSON:
{{"conclusion": "...", "is_true_positive": true/false, "is_false_positive": true/false, "learning": "...", "memory_type": "...", "trait_adjustment": {{"trait": "...", "delta": 0.0, "reason": "..."}}, "severity": "..."}}"""

PROMPT_CURIOSITY = """You are deciding what to explore next.

Available targets:
{targets}

Your personality: Openness={openness:.2f}, Conscientiousness={conscientiousness:.2f}, Extraversion={extraversion:.2f}

Rate each target's curiosity score (0-100) based on:
- Novelty (have you seen this before?)
- Anomaly (does it deviate from expected patterns?)
- Gap (is there unexplored territory nearby?)
- Potential impact (how valuable could findings here be?)

Respond as JSON:
{{"rankings": [{{"target": "...", "curiosity_score": 0, "reasoning": "...", "priority": "high/medium/low"}}]}}"""


# ── Dual-Process Mode Selection ───────────────────────────────────

# Patterns that trigger System 1 (fast, pattern-matching)
FAST_PATTERNS = {
    "wordpress", "nginx", "apache", "cloudflare", "login_form",
    "standard_dns", "standard_certificate", "common_subdomain",
}

# Patterns that trigger System 2 (slow, analytical)
SLOW_TRIGGERS = {
    "unusual_response", "anomalous_header", "unexpected_status",
    "novel_tech", "complex_api", "multi_step_vuln", "attribution",
    "pattern_across_targets", "forensic_reconstruction",
}

PROMPT_PLAN = """You are planning the next action for an exploration mission.

Target: {target}
Findings so far: {findings}
Hypotheses: {hypotheses}
Available tools: DNS lookup, HTTP crawl, certificate query, subdomain brute force

What should be done next? Consider:
1. Which hypothesis is most promising?
2. What tool/action would test it most efficiently?
3. What's the risk of this action? (rate limit, detection, false positive)

Respond as JSON:
{{"action": "...", "tool": "...", "target": "...", "reasoning": "...", "risk_level": "low/medium/high", "expected_result": "..."}}"""

PROMPT_OBSERVE = """Observe the result of an exploration action.

Action taken: {action}
Expected result: {expected}
Actual result: {result}
Raw data: {raw_data}

Analyze:
1. Did the result match expectations?
2. Was anything unexpected or anomalous?
3. What new information was revealed?
4. Are there new questions to investigate?

Respond as JSON:
{{"matched_expected": true/false, "anomalies": ["..."], "new_info": ["..."], "new_questions": ["..."], "severity": "info/low/medium/high/critical"}}"""

PROMPT_LEARN = """Learn from a completed exploration cycle.

Target: {target}
Hypothesis: {hypothesis}
Conclusion: {conclusion}
Was correct: {was_correct}
Lessons: {lessons}

What should PITBULL remember from this?
1. Is this a pattern worth storing as a semantic rule?
2. Is this a procedure worth storing (how to do something)?
3. What personality trait adjustment does this suggest?
4. Should an opinion be formed or updated?

Respond as JSON:
{{"memory_type": "episodic/semantic/procedural", "memory_content": "...", "trait_adjustment": {{"trait": "...", "delta": 0.0, "reason": "..."}}, "opinion": {{"subject": "...", "text": "...", "confidence": 0.0}} or null, "severity": "..."}}"""


class ReasoningEngine:
    """LLM-based reasoning engine with dual-process fast/slow thinking.

    Tries local model first (qwen2.5:7b), falls back to cloud (glm-5.2:cloud).
    """

    def __init__(self):
        self.base_url = settings.llm_base_url
        self.primary_model = settings.llm_model  # cloud model
        self.local_model = "qwen2.5:7b"  # local fallback
        self.client = httpx.Client(timeout=90.0)
        self._local_available = None  # cache check
        logger.info(f"Reasoning engine initialized: primary={self.primary_model}, local_fallback={self.local_model}")

    def _check_local_model(self) -> bool:
        """Check if local model is available (cached)."""
        if self._local_available is not None:
            return self._local_available
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5.0, trust_env=False)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                self._local_available = any(m.get("name") == self.local_model for m in models)
                if self._local_available:
                    logger.info(f"Local model '{self.local_model}' available — will use as primary")
                else:
                    logger.info(f"Local model '{self.local_model}' not found — using cloud only")
        except Exception:
            self._local_available = False
        return self._local_available

    def _get_model(self) -> str:
        """Get the model to use — local first, cloud fallback."""
        if self._check_local_model():
            return self.local_model
        return self.primary_model

    def _select_mode(self, finding: str, context: dict | None = None) -> str:
        """Select System 1 (fast) or System 2 (slow) based on the finding."""
        finding_lower = finding.lower()
        context = context or {}

        # Check for slow triggers
        for trigger in SLOW_TRIGGERS:
            if trigger in finding_lower or trigger in str(context.get("flags", [])).lower():
                return "slow"

        # Check for fast patterns (routine)
        fast_count = sum(1 for p in FAST_PATTERNS if p in finding_lower)
        if fast_count >= 2:
            return "fast"

        # Default: slow for novel/complex, fast for routine
        return "slow" if context.get("is_novel", False) else "fast"

    def reason_cycle(
        self,
        target: str,
        finding: str,
        raw_data: str = "",
        context: dict | None = None,
        personality: dict | None = None,
    ) -> dict[str, Any]:
        """Execute the full reasoning cycle: PERCEIVE → HYPOTHESIZE → PLAN → CONCLUDE → LEARN."""
        mode = self._select_mode(finding, context)
        result: dict[str, Any] = {
            "target": target,
            "finding": finding,
            "mode": mode,
            "perceive": {},
            "hypothesize": {},
            "plan": {},
            "conclude": {},
            "learn": {},
        }

        # PERCEIVE
        result["perceive"] = self.perceive(target, finding, raw_data, personality)

        # HYPOTHESIZE
        classification = result["perceive"].get("classification", "")
        result["hypothesize"] = self.hypothesize(target, finding, classification, personality)

        # PLAN (skip for fast mode — use direct action)
        if mode == "slow":
            findings_summary = json.dumps(result["perceive"], ensure_ascii=False)[:500]
            hypotheses = json.dumps(result["hypothesize"], ensure_ascii=False)[:500]
            prompt = PROMPT_PLAN.format(target=target, findings=findings_summary, hypotheses=hypotheses)
            result["plan"] = self._call_llm(self._system_prompt(personality), prompt)
        else:
            # Fast mode — direct action based on classification
            next_steps = result["perceive"].get("next_steps", [])
            result["plan"] = {
                "action": next_steps[0] if next_steps else "continue_exploration",
                "tool": "auto",
                "target": target,
                "reasoning": f"System 1 fast path — classified as {classification}",
                "risk_level": "low",
            }

        # CONCLUDE
        severity = result["perceive"].get("severity", "info")
        is_interesting = result["perceive"].get("is_interesting", False)
        result["conclude"] = {
            "classification": classification,
            "severity": severity,
            "is_interesting": is_interesting,
            "hypotheses": result["hypothesize"].get("hypotheses", []),
            "mode": mode,
        }

        # LEARN
        result["learn"] = self.learn(target, finding, classification, severity, mode, personality)

        return result

    def learn(
        self,
        target: str,
        finding: str,
        classification: str,
        severity: str,
        mode: str,
        personality: dict | None = None,
    ) -> dict[str, Any]:
        """Generate learning from a finding."""
        prompt = PROMPT_LEARN.format(
            target=target,
            hypothesis=classification,
            conclusion=f"Finding classified as {classification} with severity {severity}",
            was_correct=str(severity in ("medium", "high", "critical")),
            lessons=finding[:500],
        )
        return self._call_llm(self._system_prompt(personality), prompt)

    def observe(
        self,
        action: str,
        expected: str,
        result: str,
        raw_data: str = "",
        personality: dict | None = None,
    ) -> dict[str, Any]:
        """Observe and analyze the result of an action."""
        prompt = PROMPT_OBSERVE.format(action=action, expected=expected, result=result, raw_data=raw_data[:2000])
        return self._call_llm(self._system_prompt(personality), prompt)

    def _call_llm(self, system: str, prompt: str) -> dict[str, Any]:
        """Call the LLM with fallback: local first, cloud second."""
        model = self._get_model()
        try:
            resp = self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.7, "top_p": 0.9},
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
            return json.loads(content)
        except httpx.HTTPError as e:
            # If local model failed, try cloud
            if model == self.local_model and self.primary_model != self.local_model:
                logger.warning(f"Local model failed ({e}), falling back to cloud: {self.primary_model}")
                try:
                    resp = self.client.post(
                        f"{self.base_url}/api/chat",
                        json={
                            "model": self.primary_model,
                            "messages": [
                                {"role": "system", "content": system},
                                {"role": "user", "content": prompt},
                            ],
                            "format": "json",
                            "stream": False,
                            "options": {"temperature": 0.7, "top_p": 0.9},
                        },
                    )
                    resp.raise_for_status()
                    content = resp.json()["message"]["content"]
                    return json.loads(content)
                except Exception as e2:
                    logger.error(f"Cloud model also failed: {e2}")
                    return {"error": f"Both models failed: {e}, {e2}"}
            logger.error(f"LLM call failed: {e}")
            return {"error": str(e)}
        except json.JSONDecodeError as e:
            logger.error(f"LLM returned non-JSON: {e}")
            return {"error": "non-JSON response"}

    def _system_prompt(self, personality: dict | None = None) -> str:
        """Build system prompt with current personality."""
        p = personality or {
            "openness": settings.personality_openness,
            "conscientiousness": settings.personality_conscientiousness,
            "extraversion": settings.personality_extraversion,
            "agreeableness": settings.personality_agreeableness,
            "neuroticism": settings.personality_neuroticism,
            "mood": "neutral",
        }
        return SYSTEM_REASONING.format(**p)

    def perceive(self, target: str, finding: str, raw_data: str = "", personality: dict | None = None) -> dict:
        """Classify and assess a finding."""
        prompt = PROMPT_PERCEIVE.format(target=target, finding=finding, raw_data=raw_data[:2000])
        return self._call_llm(self._system_prompt(personality), prompt)

    def hypothesize(self, target: str, finding: str, classification: str = "", personality: dict | None = None) -> dict:
        """Generate hypotheses about a finding."""
        prompt = PROMPT_HYPOTHESIZE.format(target=target, finding=finding, classification=classification)
        return self._call_llm(self._system_prompt(personality), prompt)

    def conclude(self, hypothesis: str, test: str, result: str, expected: str = "", personality: dict | None = None) -> dict:
        """Conclude after testing a hypothesis."""
        prompt = PROMPT_CONCLUDE.format(hypothesis=hypothesis, test=test, result=result, expected=expected)
        return self._call_llm(self._system_prompt(personality), prompt)

    def rank_curiosity(self, targets: list[str], personality: dict | None = None) -> dict:
        """Rank targets by curiosity score."""
        targets_str = "\n".join(f"- {t}" for t in targets)
        p = personality or {}
        prompt = PROMPT_CURIOSITY.format(
            targets=targets_str,
            openness=p.get("openness", settings.personality_openness),
            conscientiousness=p.get("conscientiousness", settings.personality_conscientiousness),
            extraversion=p.get("extraversion", settings.personality_extraversion),
        )
        return self._call_llm(self._system_prompt(personality), prompt)

    def think(self, observation: str, context: str = "", personality: dict | None = None) -> dict:
        """General reasoning — the agent thinks about what it observes."""
        prompt = f"Observation: {observation}\n\nContext: {context}\n\nWhat do you think about this? What should be done next?\n\nRespond as JSON: {{\"thought\": \"...\", \"action\": \"...\", \"confidence\": 0.0}}"
        return self._call_llm(self._system_prompt(personality), prompt)


# Singleton
reasoning_engine = ReasoningEngine()