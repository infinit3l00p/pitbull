"""Cerberus Crash Triage — analyze and classify crashes.

Extracts crash signals, stack traces, and classifies by CWE.
Maps to MITRE ATT&CK techniques. Uses LLM to assess exploitability.
Generates minimal PoC for defensive validation only.

Academic basis:
- VulnLLM-R (arXiv:2512.07533): specialized reasoning for vulnerability detection
- DARPA AIxCC (arXiv:2509.07225): automated vuln detection + triage
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import signal
import uuid
from datetime import datetime
from typing import Any

import httpx

from app.config import settings
from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)

# ── CWE classification map ──────────────────────────────────────────

CWE_MAP: dict[str, dict[str, Any]] = {
    "CWE-120": {
        "name": "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
        "severity": "Critical",
        "patterns": [r"SIGSEGV", r"stack smashing", r"buffer overflow", r"__stack_chk_fail"],
        "attack_techniques": ["T1190", "T1059"],
    },
    "CWE-121": {
        "name": "Stack-based Buffer Overflow",
        "severity": "Critical",
        "patterns": [r"stack smashing detected", r"SIGSEGV.*stack", r"overflow.*stack"],
        "attack_techniques": ["T1190"],
    },
    "CWE-122": {
        "name": "Heap-based Buffer Overflow",
        "severity": "Critical",
        "patterns": [r"heap.*overflow", r"malloc.*corrupt", r"double free", r"free.*corrupt"],
        "attack_techniques": ["T1190", "T1068"],
    },
    "CWE-416": {
        "name": "Use After Free",
        "severity": "Critical",
        "patterns": [r"use.after.free", r"double free", r"free.*use", r"UAF"],
        "attack_techniques": ["T1059", "T1068"],
    },
    "CWE-415": {
        "name": "Double Free",
        "severity": "High",
        "patterns": [r"double free", r"free.*already.*free"],
        "attack_techniques": ["T1059"],
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "severity": "Medium",
        "patterns": [r"SIGSEGV.*null", r"null.*deref", r"NULL.*pointer", r"0x0.*SIGSEGV"],
        "attack_techniques": ["T1499"],  # Endpoint DoS
    },
    "CWE-190": {
        "name": "Integer Overflow or Wraparound",
        "severity": "High",
        "patterns": [r"integer.*overflow", r"arithmetic.*overflow", r"wrap.*around"],
        "attack_techniques": ["T1190"],
    },
    "CWE-191": {
        "name": "Integer Underflow (Wraparound)",
        "severity": "High",
        "patterns": [r"integer.*underflow", r"underflow"],
        "attack_techniques": ["T1190"],
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "severity": "Medium",
        "patterns": [r"out.of.bounds.*read", r"read.*overflow", r"ASAN.*read"],
        "attack_techniques": ["T1190"],
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "severity": "Critical",
        "patterns": [r"out.of.bounds.*write", r"write.*overflow", r"ASAN.*write", r"heap-buffer-overflow"],
        "attack_techniques": ["T1190", "T1059"],
    },
    "CWE-134": {
        "name": "Uncontrolled Format String",
        "severity": "High",
        "patterns": [r"format.*string", r"%n.*%x.*%s", r"format.*vuln"],
        "attack_techniques": ["T1190", "T1059"],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "severity": "High",
        "patterns": [r"path.*traversal", r"directory.*traversal", r"\.\.\/"],
        "attack_techniques": ["T1083", "T1190"],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "severity": "Critical",
        "patterns": [r"command.*injection", r"OS.*command", r"shell.*injection"],
        "attack_techniques": ["T1059", "T1190"],
    },
    "CWE-89": {
        "name": "SQL Injection",
        "severity": "Critical",
        "patterns": [r"SQL.*injection", r"SQL.*syntax", r"SQLSTATE"],
        "attack_techniques": ["T1190"],
    },
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "severity": "Medium",
        "patterns": [r"XSS", r"cross.site.*script", r"<script>"],
        "attack_techniques": ["T1059.007"],
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption (DoS)",
        "severity": "Medium",
        "patterns": [r"timeout", r"hang", r"resource.*exhaust", r"OOM", r"out.of.memory"],
        "attack_techniques": ["T1499"],
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "severity": "Medium",
        "patterns": [r"input.*validation", r"invalid.*input", r"unexpected.*input"],
        "attack_techniques": ["T1190"],
    },
    "CWE-119": {
        "name": "Improper Restriction of Operations within Bounds of Memory Buffer",
        "severity": "Critical",
        "patterns": [r"memory.*buffer", r"bounds.*check", r"SIGSEGV"],
        "attack_techniques": ["T1190", "T1059"],
    },
}

# Reverse map for ATT&CK to CWE
ATTACK_TO_CWE: dict[str, list[str]] = {}
for cwe_id, info in CWE_MAP.items():
    for technique in info["attack_techniques"]:
        ATTACK_TO_CWE.setdefault(technique, []).append(cwe_id)

# Signal to likely CWE mapping
SIGNAL_CWE_MAP: dict[int, list[str]] = {
    signal.SIGSEGV: ["CWE-120", "CWE-121", "CWE-122", "CWE-476", "CWE-125", "CWE-787", "CWE-119"],
    signal.SIGABRT: ["CWE-416", "CWE-415", "CWE-122"],
    signal.SIGFPE: ["CWE-190", "CWE-191"],
    signal.SIGBUS: ["CWE-125", "CWE-787"],
    signal.SIGILL: ["CWE-119"],
    signal.SIGSYS: ["CWE-20"],
}


class CrashTriage:
    """Analyze and classify crashes to determine vulnerability status."""

    def __init__(self) -> None:
        self.base_url = settings.llm_base_url
        self.primary_model = settings.llm_model
        self.local_model = "qwen2.5:7b"
        self._local_available: bool | None = None
        self.client = httpx.Client(timeout=60.0)

    # ── LLM helpers ────────────────────────────────────────────────

    def _check_local_model(self) -> bool:
        if self._local_available is not None:
            return self._local_available
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                self._local_available = any(m.get("name") == self.local_model for m in models)
        except Exception:
            self._local_available = False
        return self._local_available

    def _get_model(self) -> str:
        if self._check_local_model():
            return self.local_model
        return self.primary_model

    def _parse_json_response(self, content: str) -> dict[str, Any]:
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            content = "\n".join(lines).strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        first = content.find("{")
        last = content.rfind("}")
        if first != -1 and last != -1 and last > first:
            try:
                return json.loads(content[first:last+1])
            except json.JSONDecodeError:
                pass
        logger.error(f"Could not parse LLM response as JSON: {content[:200]}")
        return {"error": "non-JSON response", "raw": content[:500]}

    def _call_llm(self, system: str, prompt: str) -> dict[str, Any]:
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
                    "options": {"temperature": 0.3, "top_p": 0.9},
                },
            )
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
            return self._parse_json_response(content)
        except httpx.HTTPError as e:
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
                            "options": {"temperature": 0.3, "top_p": 0.9},
                        },
                    )
                    resp.raise_for_status()
                    content = resp.json()["message"]["content"]
                    return self._parse_json_response(content)
                except Exception as e2:
                    logger.error(f"Cloud model also failed: {e2}")
                    return {"error": f"Both models failed: {e}, {e2}"}
            logger.error(f"LLM call failed: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return {"error": str(e)}

    # ── Crash triage ────────────────────────────────────────────────

    def triage_crash(self, crash_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze a crash to determine if it's a real vulnerability.

        Extracts crash signal, faulting instruction, stack trace.
        Classifies by CWE and maps to MITRE ATT&CK.
        Assesses severity and exploitability.
        """
        result: dict[str, Any] = {
            "triage_id": str(uuid.uuid4())[:8],
            "triaged_at": datetime.now().isoformat(),
            "is_vulnerability": False,
            "cwe_class": "CWE-20",  # Default: improper input validation
            "cwe_name": "",
            "severity": "Low",
            "exploitability": "unknown",
            "attack_techniques": [],
            "stack_trace_hash": "",
            "dedup_key": "",
        }

        # Extract crash signal
        sig = crash_data.get("signal", 0)
        sig_name = crash_data.get("signal_name", "")
        result["signal"] = sig
        result["signal_name"] = sig_name

        # Extract stack trace
        stderr = crash_data.get("stderr", "") or crash_data.get("stack_trace", "")
        stdout = crash_data.get("stdout", "")
        all_output = f"{stderr}\n{stdout}"

        stack_trace = self._extract_stack_trace(all_output)
        result["stack_trace"] = stack_trace
        result["stack_trace_hash"] = self._hash_stack_trace(stack_trace)
        result["dedup_key"] = result["stack_trace_hash"] or f"sig:{sig}"

        # Classify by CWE using pattern matching
        cwe_class, cwe_info = self._classify_cwe(sig, all_output)
        result["cwe_class"] = cwe_class
        result["cwe_name"] = cwe_info.get("name", "")
        result["severity"] = cwe_info.get("severity", "Low")
        result["attack_techniques"] = cwe_info.get("attack_techniques", [])

        # Determine if this is a real vulnerability
        if sig in (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS, signal.SIGFPE, signal.SIGILL):
            result["is_vulnerability"] = True
        elif crash_data.get("possible_crash"):
            # Network crash — need more analysis
            result["is_vulnerability"] = True
            result["severity"] = "Medium"  # Conservative
        elif crash_data.get("hang") or crash_data.get("timeout"):
            result["is_vulnerability"] = True
            result["cwe_class"] = "CWE-400"
            result["cwe_name"] = CWE_MAP["CWE-400"]["name"]
            result["severity"] = "Medium"
            result["attack_techniques"] = CWE_MAP["CWE-400"]["attack_techniques"]

        # LLM analysis for exploitability assessment
        llm_analysis = self._llm_triage(crash_data, result)
        if "error" not in llm_analysis:
            result["llm_analysis"] = llm_analysis
            # Override with LLM assessment if more specific
            if llm_analysis.get("exploitability"):
                result["exploitability"] = llm_analysis["exploitability"]
            if llm_analysis.get("severity"):
                result["severity"] = llm_analysis["severity"]
            if llm_analysis.get("cwe_class") and llm_analysis["cwe_class"] != "CWE-20":
                result["cwe_class"] = llm_analysis["cwe_class"]
                result["cwe_name"] = CWE_MAP.get(llm_analysis["cwe_class"], {}).get("name", "")

        return result

    def _extract_stack_trace(self, output: str) -> str:
        """Extract stack trace from crash output."""
        lines = output.split("\n")
        trace_lines: list[str] = []

        # Common stack trace patterns
        trace_patterns = [
            r"^#\d+\s+",  # GDB format: #0 0x...
            r"^\s*at\s+",  # Java/JS format
            r"^\s*File\s+\"",  # Python format
            r"^\s*\w+\s+\(.*\)\s+\[",  # Python traceback
            r"^Traceback\s",
            r"^Backtrace:",
            r"^Program received signal",
            r"^\s*→\s+",  # Arrow format
            r"^\s*frame\s+#?\d+",
        ]

        in_trace = False
        for line in lines:
            for pattern in trace_patterns:
                if re.match(pattern, line):
                    in_trace = True
                    trace_lines.append(line)
                    break
            if in_trace and not line.strip():
                break  # End of trace

        return "\n".join(trace_lines[:50]) if trace_lines else output[:500]

    def _hash_stack_trace(self, trace: str) -> str:
        """Generate a hash for stack trace deduplication."""
        if not trace:
            return ""
        # Normalize: remove addresses, line numbers, keep function names
        normalized = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", trace)
        normalized = re.sub(r":\d+", ":LINE", normalized)
        normalized = re.sub(r"#\d+", "#N", normalized)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _classify_cwe(self, sig: int, output: str) -> tuple[str, dict[str, Any]]:
        """Classify crash by CWE using signal and output patterns."""
        output_lower = output.lower()

        # Check pattern-based classification first
        for cwe_id, cwe_info in CWE_MAP.items():
            for pattern in cwe_info["patterns"]:
                if re.search(pattern, output_lower):
                    return cwe_id, cwe_info

        # Fall back to signal-based classification
        if sig in SIGNAL_CWE_MAP:
            cwe_id = SIGNAL_CWE_MAP[sig][0]  # Most likely CWE for this signal
            return cwe_id, CWE_MAP.get(cwe_id, {"name": "Unknown", "severity": "Medium", "attack_techniques": []})

        return "CWE-20", CWE_MAP["CWE-20"]

    def _llm_triage(self, crash_data: dict[str, Any], initial_analysis: dict[str, Any]) -> dict[str, Any]:
        """Use LLM to assess crash exploitability."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security researcher. "
            "You analyze crashes to determine exploitability and classify "
            "vulnerabilities. DEFENSIVE RESEARCH ONLY. Respond in JSON only."
        )
        prompt = f"""Analyze this crash and assess its exploitability:

Crash data:
{json.dumps(crash_data, ensure_ascii=False, default=str)[:1500]}

Initial analysis:
{json.dumps(initial_analysis, ensure_ascii=False, default=str)[:500]}

Assess:
1. Is this a real vulnerability or a benign crash?
2. What CWE class best fits this crash?
3. What is the severity? (Critical/High/Medium/Low)
4. How exploitable is this? (high/medium/low/none)
5. What MITRE ATT&CK techniques apply?

Respond as JSON:
{{
  "is_vulnerability": true/false,
  "cwe_class": "CWE-XXX",
  "severity": "Critical/High/Medium/Low",
  "exploitability": "high/medium/low/none",
  "exploitability_reason": "why this assessment",
  "attack_techniques": ["TXXXX"],
  "recommended_action": "what to do next",
  "false_positive_indicators": ["signs this might not be a real vuln"]
}}"""
        return self._call_llm(system, prompt)

    # ── PoC generation (defensive validation only) ──────────────────

    def generate_poc(self, crash_info: dict[str, Any]) -> dict[str, Any]:
        """Generate a minimal proof-of-concept for defensive validation.

        This creates a NON-DESTRUCTIVE PoC that reproduces the crash
        for validation purposes only. No weaponization.
        """
        system = (
            "You are PITBULL-Cerberus, an autonomous security researcher. "
            "You generate MINIMAL proof-of-concept inputs to reproduce crashes "
            "for DEFENSIVE VALIDATION ONLY. No weaponization, no exploit code. "
            "Respond in JSON only."
        )
        prompt = f"""Generate a minimal proof-of-concept to reproduce this crash:

Crash info:
{json.dumps(crash_info, ensure_ascii=False, default=str)[:1500]}

Requirements:
1. The PoC must be NON-DESTRUCTIVE — it should only reproduce the crash
2. Minimize the input — shortest input that triggers the bug
3. Include a description of what the PoC does
4. Include expected behavior (what should happen when the PoC is run)
5. DO NOT include exploit code, shellcode, or weaponization

Respond as JSON:
{{
  "poc_input": "the minimal input that reproduces the crash",
  "poc_b64": "base64 encoded version",
  "description": "what the PoC does",
  "expected_behavior": "what should happen",
  "reproduction_steps": ["step 1", "step 2", ...],
  "safety_notes": "why this PoC is safe to run"
}}"""
        result = self._call_llm(system, prompt)
        if "error" in result:
            # Fallback: use the original crash input
            return {
                "poc_input": crash_info.get("input", ""),
                "poc_b64": crash_info.get("input_b64", ""),
                "description": "Original crash input (LLM unavailable for optimization)",
                "expected_behavior": f"Should trigger {crash_info.get('signal_name', 'crash')}",
                "reproduction_steps": ["Run the target with the PoC input"],
                "safety_notes": "This is the original crash input, not a weaponized exploit",
            }
        return result

    # ── Deduplication ───────────────────────────────────────────────

    def deduplicate_crashes(self, crashes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate crashes by stack trace hash."""
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for crash in crashes:
            triage = self.triage_crash(crash)
            dedup_key = triage["dedup_key"]
            if dedup_key not in seen:
                seen.add(dedup_key)
                crash["triage"] = triage
                unique.append(crash)
        return unique

    # ── CWE classes ─────────────────────────────────────────────────

    @staticmethod
    def get_cwe_classes() -> list[dict[str, Any]]:
        """Return all known CWE classes."""
        return [
            {
                "cwe_id": cwe_id,
                "name": info["name"],
                "severity": info["severity"],
                "attack_techniques": info["attack_techniques"],
            }
            for cwe_id, info in CWE_MAP.items()
        ]


# Singleton
_triage: CrashTriage | None = None


def get_triage() -> CrashTriage:
    """Get or create the CrashTriage singleton."""
    global _triage
    if _triage is None:
        _triage = CrashTriage()
    return _triage