"""Cerberus LLM-Guided Fuzzer — main fuzzing orchestrator.

Uses LLM to generate intelligent test inputs via multiple strategies:
- Mutation-based: LLM analyzes existing inputs and generates variations
- Grammar-based: LLM generates inputs following protocol/format grammar
- Path-guided: LLM suggests inputs to reach uncovered code paths
- Semantic: LLM uses understanding of the target to generate inputs likely to trigger bugs

Academic basis:
- LLAMAFUZZ (arXiv:2406.07714): LLM enhances greybox fuzzing
- ELFuzz (arXiv:2506.10323): LLM synthesizes fuzzing strategies at meta-level
- Hybrid Fuzzing with LLM-Guided Input Mutation (arXiv:2511.03995)
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime
from typing import Any

import httpx

from app.config import settings
from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)


class LLMFuzzer:
    """LLM-guided fuzzing orchestrator.

    Runs fuzzing campaigns against binary or network targets using
    LLM-generated inputs. Monitors for crashes, hangs, and unexpected behavior.
    """

    def __init__(self) -> None:
        self.base_url = settings.llm_base_url
        self.primary_model = settings.llm_model
        self.local_model = "qwen2.5:7b"
        self._local_available: bool | None = None
        self.client = httpx.Client(timeout=120.0)

        # Campaign state
        self._active_campaign: dict[str, Any] | None = None
        self._stop_flag = asyncio.Event()

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
                    "options": {"temperature": 0.7, "top_p": 0.95},
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
                            "options": {"temperature": 0.7, "top_p": 0.95},
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

    # ── Seed input generation ───────────────────────────────────────

    def _generate_seed_inputs(self, target_info: dict[str, Any], strategy: str) -> list[str]:
        """Generate initial seed inputs using LLM."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You generate seed inputs for fuzzing campaigns. "
            "All inputs are for DEFENSIVE RESEARCH ONLY. "
            "Respond in JSON only."
        )
        prompt = f"""Generate 10 seed inputs for fuzzing this target:

Target: {json.dumps(target_info, ensure_ascii=False, default=str)[:1500]}
Strategy: {strategy}

Generate inputs that are:
1. Valid enough to be accepted by the target
2. Edge-case oriented (boundary values, special characters)
3. Non-destructive (for initial seeds)
4. Varied (different lengths, encodings, formats)

Respond as JSON:
{{
  "seeds": ["seed1", "seed2", ...],
  "rationale": "why these seeds were chosen"
}}"""
        result = self._call_llm(system, prompt)
        if "error" in result:
            # Fallback seeds
            return ["", "A", "\x00", "AAAA", "\xff" * 100, "test", "1", "-1", "0", "a" * 1000]
        return result.get("seeds", ["", "A", "\x00", "AAAA"])

    # ── Mutation strategies ─────────────────────────────────────────

    def _llm_mutate_input(self, seed: str, target_info: dict[str, Any], feedback: dict[str, Any] | None = None) -> list[str]:
        """Use LLM to generate mutations of a seed input."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You generate input mutations to discover vulnerabilities. "
            "DEFENSIVE RESEARCH ONLY. Respond in JSON only."
        )
        feedback_str = json.dumps(feedback, ensure_ascii=False, default=str)[:500] if feedback else "none"
        prompt = f"""Generate 5 mutations of this input for fuzzing:

Seed input (base64): {base64.b64encode(seed.encode('utf-8', errors='replace')).decode() if seed else "(empty)"}
Seed input (raw): {repr(seed)[:200]}
Target: {json.dumps(target_info, ensure_ascii=False, default=str)[:800]}
Previous feedback: {feedback_str}

Mutation strategies to apply:
- Bit/byte flipping
- Boundary value insertion (INT_MAX, 0, -1, very long strings)
- Format string injection (%s, %x, %n)
- Special character insertion (\\x00, \\n, \\r, \\xff, unicode)
- Structural mutation (truncate, duplicate, reorder)
- Type confusion (send string where int expected, etc.)

Respond as JSON:
{{
  "mutations": ["mut1", "mut2", "mut3", "mut4", "mut5"],
  "strategy_used": "description of mutation approach",
  "targeted_bugs": ["what bugs these mutations might trigger"]
}}"""
        result = self._call_llm(system, prompt)
        if "error" in result:
            # Heuristic mutations
            return self._heuristic_mutations(seed)
        return result.get("mutations", self._heuristic_mutations(seed))

    def _heuristic_mutations(self, seed: str) -> list[str]:
        """Generate heuristic mutations when LLM is unavailable."""
        mutations: list[str] = []
        # Bit flip
        if seed:
            flipped = list(seed)
            if flipped:
                flipped[0] = chr(ord(flipped[0]) ^ 0x01)
                mutations.append("".join(flipped))
        # Boundary values
        mutations.extend([
            seed + "\x00",
            seed * 10,
            seed + "A" * 256,
            "\x00" * (len(seed) + 1),
            seed + "%s%s%s%n%x%x",
        ])
        return mutations[:5]

    def _llm_grammar_input(self, target_info: dict[str, Any], grammar: dict[str, Any] | None = None) -> list[str]:
        """Use LLM to generate grammar-based inputs."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You generate inputs following protocol/format grammars. "
            "DEFENSIVE RESEARCH ONLY. Respond in JSON only."
        )
        grammar_str = json.dumps(grammar, ensure_ascii=False)[:500] if grammar else "infer from target"
        prompt = f"""Generate 5 grammar-based inputs for fuzzing this target:

Target: {json.dumps(target_info, ensure_ascii=False, default=str)[:800]}
Grammar: {grammar_str}

Generate inputs that:
1. Follow the expected protocol/format structure
2. Include valid but edge-case values
3. Test protocol state transitions
4. Include malformed but close-to-valid inputs
5. Test boundary conditions within the grammar

Respond as JSON:
{{
  "inputs": ["input1", "input2", "input3", "input4", "input5"],
  "grammar_inferred": "description of inferred grammar",
  "states_tested": ["protocol states being tested"]
}}"""
        result = self._call_llm(system, prompt)
        if "error" in result:
            return ["", "A", "\x00", "AAAA", "\xff" * 100]
        return result.get("inputs", ["", "A", "\x00", "AAAA"])

    def _llm_semantic_input(self, target_info: dict[str, Any], previous_crashes: list[dict[str, Any]] | None = None) -> list[str]:
        """Use LLM semantic understanding to generate targeted inputs."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You use semantic understanding of targets to generate inputs "
            "likely to trigger vulnerabilities. DEFENSIVE RESEARCH ONLY. "
            "Respond in JSON only."
        )
        crashes_str = json.dumps(previous_crashes[-5:], ensure_ascii=False, default=str)[:800] if previous_crashes else "none"
        prompt = f"""Generate 5 semantically-targeted inputs for fuzzing:

Target: {json.dumps(target_info, ensure_ascii=False, default=str)[:800]}
Previous crashes: {crashes_str}

Use your understanding of:
- Common vulnerability patterns (buffer overflow, integer overflow, format string, etc.)
- The target's likely input processing logic
- Previous crash patterns to guide new inputs
- Edge cases specific to the target type

Respond as JSON:
{{
  "inputs": ["input1", "input2", "input3", "input4", "input5"],
  "targeted_vulnerabilities": ["CWE-120", "CWE-190", etc.],
  "reasoning": "why these inputs should trigger bugs"
}}"""
        result = self._call_llm(system, prompt)
        if "error" in result:
            return ["", "A" * 1000, "\x00" * 100, "%n%n%n%n", "\xff" * 256]
        return result.get("inputs", ["", "A" * 1000, "\x00" * 100])

    def _llm_path_guided_input(self, target_info: dict[str, Any], coverage: dict[str, Any] | None = None) -> list[str]:
        """Use LLM to suggest inputs for uncovered code paths."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You suggest inputs to reach uncovered code paths. "
            "DEFENSIVE RESEARCH ONLY. Respond in JSON only."
        )
        coverage_str = json.dumps(coverage, ensure_ascii=False, default=str)[:500] if coverage else "no coverage data available"
        prompt = f"""Suggest 5 inputs to reach uncovered code paths:

Target: {json.dumps(target_info, ensure_ascii=False, default=str)[:800]}
Coverage info: {coverage_str}

Consider:
- Which input values might trigger different code branches
- Boundary conditions that might switch control flow
- Error handling paths that need specific input patterns
- Protocol state transitions that require specific sequences

Respond as JSON:
{{
  "inputs": ["input1", "input2", "input3", "input4", "input5"],
  "targeted_paths": ["description of paths each input targets"],
  "branch_conditions": ["what branch conditions these inputs test"]
}}"""
        result = self._call_llm(system, prompt)
        if "error" in result:
            return ["", "A", "\x00", "AAAA", "test"]
        return result.get("inputs", ["", "A", "\x00"])

    # ── Target execution ────────────────────────────────────────────

    async def _execute_binary(self, binary_path: str, input_data: str, timeout: float = 10.0) -> dict[str, Any]:
        """Execute a binary with given input and monitor for crashes."""
        result: dict[str, Any] = {
            "input": input_data[:200],
            "input_b64": base64.b64encode(input_data.encode("utf-8", errors="replace")).decode(),
            "timestamp": datetime.now().isoformat(),
        }

        try:
            proc = await asyncio.create_subprocess_exec(
                binary_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=input_data.encode("utf-8", errors="replace")),
                    timeout=timeout,
                )
                result["exit_code"] = proc.returncode
                result["stdout"] = stdout.decode("utf-8", errors="replace")[:500]
                result["stderr"] = stderr.decode("utf-8", errors="replace")[:500]

                # Check for crash signals
                if proc.returncode and proc.returncode < 0:
                    sig = -proc.returncode
                    result["crash"] = True
                    result["signal"] = sig
                    try:
                        result["signal_name"] = signal.Signals(sig).name
                    except (ValueError, AttributeError):
                        result["signal_name"] = f"SIG{sig}"
                elif proc.returncode and proc.returncode > 128:
                    # Also indicates signal on some systems
                    sig = proc.returncode - 128
                    result["crash"] = True
                    result["signal"] = sig
                    try:
                        result["signal_name"] = signal.Signals(sig).name
                    except (ValueError, AttributeError):
                        result["signal_name"] = f"SIG{sig}"

            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result["timeout"] = True
                result["hang"] = True

        except FileNotFoundError:
            result["error"] = f"Binary not found: {binary_path}"
        except PermissionError:
            result["error"] = f"Permission denied: {binary_path}"
        except Exception as e:
            result["error"] = str(e)

        return result

    async def _execute_network(self, host: str, port: int, input_data: str, timeout: float = 10.0) -> dict[str, Any]:
        """Send input to a network target and monitor for crashes/errors."""
        result: dict[str, Any] = {
            "input": input_data[:200],
            "input_b64": base64.b64encode(input_data.encode("utf-8", errors="replace")).decode(),
            "host": host,
            "port": port,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
            writer.write(input_data.encode("utf-8", errors="replace"))
            await writer.drain()

            try:
                response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                result["response"] = response.decode("utf-8", errors="replace")[:500]
                result["response_b64"] = base64.b64encode(response).decode()
                result["connection_closed"] = False
            except asyncio.TimeoutError:
                result["timeout"] = True
                result["hang"] = True

            # Check if connection was closed by server (possible crash)
            if writer.is_closing():
                result["connection_closed"] = True
                result["possible_crash"] = True

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except ConnectionRefusedError:
            result["error"] = "Connection refused"
            result["possible_crash"] = True
        except asyncio.TimeoutError:
            result["error"] = "Connection timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    async def _execute_api(self, url: str, input_data: str, method: str = "POST", timeout: float = 10.0) -> dict[str, Any]:
        """Send input to an API endpoint and monitor for errors."""
        result: dict[str, Any] = {
            "input": input_data[:200],
            "url": url,
            "method": method,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                # Try to parse input as JSON for body
                try:
                    body = json.loads(input_data)
                    resp = await client.request(method, url, json=body)
                except (json.JSONDecodeError, ValueError):
                    resp = await client.request(method, url, content=input_data)

                result["status_code"] = resp.status_code
                result["response"] = resp.text[:500]
                result["headers"] = dict(resp.headers)

                # Check for error indicators
                if resp.status_code >= 500:
                    result["server_error"] = True
                    result["possible_crash"] = True
                elif resp.status_code == 429:
                    result["rate_limited"] = True

        except httpx.TimeoutException:
            result["timeout"] = True
            result["hang"] = True
        except httpx.HTTPError as e:
            result["error"] = str(e)
            result["possible_crash"] = True
        except Exception as e:
            result["error"] = str(e)

        return result

    # ── Main fuzzing campaign ──────────────────────────────────────

    async def fuzz(
        self,
        target: str,
        strategy: str = "mutation",
        iterations: int = 1000,
        delay_ms: int = 100,
        target_info: dict[str, Any] | None = None,
        target_type: str = "binary",
    ) -> dict[str, Any]:
        """Run a fuzzing campaign.

        Args:
            target: Binary path, host:port, or URL
            strategy: "mutation", "grammar", "semantic", "path-guided", or "hybrid"
            iterations: Maximum number of inputs to try
            delay_ms: Delay between inputs in milliseconds
            target_info: Pre-analyzed target info (optional)
            target_type: "binary", "protocol", or "api"
        """
        campaign_id = str(uuid.uuid4())[:8]
        self._stop_flag.clear()

        self._active_campaign = {
            "campaign_id": campaign_id,
            "target": target,
            "strategy": strategy,
            "target_type": target_type,
            "iterations_requested": iterations,
            "iterations_run": 0,
            "crashes_found": 0,
            "unique_crashes": 0,
            "hangs_found": 0,
            "errors_found": 0,
            "coverage_edges": 0,
            "started_at": datetime.now().isoformat(),
            "status": "running",
            "crashes": [],
            "events": [],
            "seen_crash_hashes": set(),
        }

        # If no target info, do minimal analysis
        if target_info is None:
            target_info = {"target": target, "type": target_type}

        # Generate seed inputs
        seeds = self._generate_seed_inputs(target_info, strategy)
        self._log_event(campaign_id, "info", f"Generated {len(seeds)} seed inputs")

        # Fuzzing loop
        input_queue = list(seeds)
        iteration = 0

        while iteration < iterations and not self._stop_flag.is_set():
            # Get next input
            if not input_queue:
                # Generate new inputs based on strategy
                if strategy == "mutation":
                    seed = seeds[iteration % len(seeds)] if seeds else ""
                    new_inputs = self._llm_mutate_input(seed, target_info)
                elif strategy == "grammar":
                    new_inputs = self._llm_grammar_input(target_info)
                elif strategy == "semantic":
                    new_inputs = self._llm_semantic_input(
                        target_info,
                        self._active_campaign.get("crashes", []),
                    )
                elif strategy == "path-guided":
                    coverage = {"edges_seen": self._active_campaign.get("coverage_edges", 0)}
                    new_inputs = self._llm_path_guided_input(target_info, coverage)
                elif strategy == "hybrid":
                    # Cycle through all strategies
                    cycle = iteration % 4
                    if cycle == 0:
                        seed = seeds[iteration % len(seeds)] if seeds else ""
                        new_inputs = self._llm_mutate_input(seed, target_info)
                    elif cycle == 1:
                        new_inputs = self._llm_grammar_input(target_info)
                    elif cycle == 2:
                        new_inputs = self._llm_semantic_input(
                            target_info,
                            self._active_campaign.get("crashes", []),
                        )
                    else:
                        new_inputs = self._llm_path_guided_input(target_info)
                else:
                    new_inputs = self._heuristic_mutations(seeds[0] if seeds else "")

                input_queue.extend(new_inputs)

            input_data = input_queue.pop(0)

            # Execute the input
            if target_type == "binary":
                exec_result = await self._execute_binary(target, input_data)
            elif target_type == "protocol":
                parts = target.split(":")
                host = parts[0] if len(parts) > 1 else "127.0.0.1"
                port = int(parts[1]) if len(parts) > 1 else 80
                exec_result = await self._execute_network(host, port, input_data)
            elif target_type == "api":
                exec_result = await self._execute_api(target, input_data)
            else:
                exec_result = {"error": f"Unknown target type: {target_type}"}

            self._active_campaign["iterations_run"] = iteration + 1

            # Analyze result
            if exec_result.get("crash") or exec_result.get("possible_crash"):
                self._active_campaign["crashes_found"] += 1
                crash_hash = self._hash_crash(exec_result)
                if crash_hash not in self._active_campaign["seen_crash_hashes"]:
                    self._active_campaign["seen_crash_hashes"].add(crash_hash)
                    self._active_campaign["unique_crashes"] += 1
                    self._active_campaign["crashes"].append(exec_result)
                    self._log_event(campaign_id, "crash", f"Unique crash found! Signal: {exec_result.get('signal_name', 'unknown')}")
                    # Store in Neo4j
                    await self._store_crash(campaign_id, target, exec_result)
                else:
                    self._log_event(campaign_id, "crash", f"Duplicate crash (signal: {exec_result.get('signal_name', 'unknown')})")
            elif exec_result.get("hang") or exec_result.get("timeout"):
                self._active_campaign["hangs_found"] += 1
                self._log_event(campaign_id, "hang", f"Timeout/hang detected at iteration {iteration}")
            elif exec_result.get("error"):
                self._active_campaign["errors_found"] += 1

            # Emit progress event
            if iteration % 10 == 0:
                self._log_event(campaign_id, "progress", {
                    "iteration": iteration,
                    "crashes": self._active_campaign["crashes_found"],
                    "unique_crashes": self._active_campaign["unique_crashes"],
                    "hangs": self._active_campaign["hangs_found"],
                })

            # Rate limit
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)

            iteration += 1

        # Campaign complete
        self._active_campaign["status"] = "completed" if not self._stop_flag.is_set() else "stopped"
        self._active_campaign["completed_at"] = datetime.now().isoformat()
        self._log_event(campaign_id, "done", f"Campaign {self._active_campaign['status']}")

        # Convert set to list for serialization
        self._active_campaign["seen_crash_hashes"] = list(self._active_campaign["seen_crash_hashes"])

        return self._active_campaign

    def stop(self) -> None:
        """Stop the active fuzzing campaign."""
        self._stop_flag.set()

    def get_status(self) -> dict[str, Any] | None:
        """Get current campaign status."""
        if self._active_campaign is None:
            return None
        status = {k: v for k, v in self._active_campaign.items() if k != "seen_crash_hashes"}
        status["seen_crash_hashes"] = list(self._active_campaign.get("seen_crash_hashes", set()))
        return status

    # ── Helpers ─────────────────────────────────────────────────────

    def _log_event(self, campaign_id: str, event_type: str, data: Any) -> None:
        """Log a campaign event."""
        if self._active_campaign is None:
            return
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "data": data if isinstance(data, (str, dict, list)) else str(data),
        }
        self._active_campaign["events"].append(event)

    def _hash_crash(self, crash_data: dict[str, Any]) -> str:
        """Generate a hash for crash deduplication."""
        import hashlib
        key_parts = [
            str(crash_data.get("signal", "")),
            str(crash_data.get("exit_code", "")),
            str(crash_data.get("error", ""))[:100],
            crash_data.get("stderr", "")[:200] if crash_data.get("stderr") else "",
        ]
        return hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:16]

    async def _store_crash(self, campaign_id: str, target: str, crash_data: dict[str, Any]) -> None:
        """Store a crash finding in Neo4j."""
        try:
            finding_id = f"ZD-{uuid.uuid4().hex[:8]}"
            cypher_write(
                """
                CREATE (z:ZeroDayFinding {
                    finding_id: $finding_id,
                    target: $target,
                    campaign_id: $campaign_id,
                    vuln_type: $vuln_type,
                    cwe_class: $cwe_class,
                    severity: $severity,
                    description: $description,
                    poc_code: $poc_code,
                    stack_trace: $stack_trace,
                    signal: $signal,
                    exit_code: $exit_code,
                    discovered_at: $discovered_at,
                    status: 'new'
                })
                """,
                {
                    "finding_id": finding_id,
                    "target": target,
                    "campaign_id": campaign_id,
                    "vuln_type": "crash",
                    "cwe_class": "TBD",  # Will be filled by crash_triage
                    "severity": "TBD",
                    "description": f"Crash with signal {crash_data.get('signal_name', 'unknown')} during fuzzing",
                    "poc_code": crash_data.get("input_b64", ""),
                    "stack_trace": crash_data.get("stderr", "")[:2000],
                    "signal": crash_data.get("signal", 0),
                    "exit_code": crash_data.get("exit_code", 0),
                    "discovered_at": datetime.now().isoformat(),
                },
            )
        except Exception as e:
            logger.error(f"Failed to store crash in Neo4j: {e}")


# Singleton
_fuzzer: LLMFuzzer | None = None


def get_fuzzer() -> LLMFuzzer:
    """Get or create the LLMFuzzer singleton."""
    global _fuzzer
    if _fuzzer is None:
        _fuzzer = LLMFuzzer()
    return _fuzzer