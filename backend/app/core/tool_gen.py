"""PITBULL Tool Generation — LLM generates custom scripts for capability gaps.

When PITBULL encounters a situation it can't handle with existing tools:
1. Describe the gap
2. Generate a Python script using LLM
3. Test the script
4. If successful, add to tool library
5. Log the generation

Academic basis:
- Recon-Act (arXiv:2509.21072): self-evolving tool generation
- PenForge (arXiv:2601.06910): dynamic expert agent construction
- Galaxy (arXiv:2508.03991): proactive capability expansion
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from app.config import settings
from app.core.database import cypher_write

logger = logging.getLogger(__name__)

TOOL_LIBRARY_DIR = Path(settings.state_dir) / "tools"
TOOL_REGISTRY = Path(settings.state_dir) / "tool_registry.jsonl"


TOOL_GEN_PROMPT = """You are PITBULL, an autonomous digital explorer. You need to generate a Python tool to fill a capability gap.

Gap description: {gap}
Context: {context}
Target: {target}

Generate a complete, self-contained Python script that:
1. Can be run independently
2. Uses only standard library + httpx (available)
3. Takes target as first argument
4. Outputs JSON results to stdout
5. Handles errors gracefully
6. Has rate limiting (0.5s between requests)
7. Is safe — no destructive actions, only observation

Respond with ONLY the Python code, no markdown fences, no explanation."""


class ToolGenerator:
    """Generates, tests, and stores custom exploration tools."""

    def __init__(self):
        self.base_url = settings.llm_base_url
        self.primary_model = settings.llm_model
        self.local_model = "qwen2.5:7b"
        self._local_available = None
        self.client = httpx.Client(timeout=120.0)
        TOOL_LIBRARY_DIR.mkdir(parents=True, exist_ok=True)

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

    def identify_gap(self, findings: list[dict[str, Any]], existing_tools: list[str]) -> str | None:
        """Identify a capability gap from current findings."""
        # Check for situations we can't handle
        for finding in findings:
            content = str(finding.get("content", "")).lower()
            url = str(finding.get("url", finding.get("target", ""))).lower()

            # GraphQL endpoint found but no GraphQL tool
            if "graphql" in content and not any("graphql" in t for t in existing_tools):
                return "GraphQL introspection query tool — test if introspection is enabled"

            # API found but no API fuzzer
            if "/api/" in url and not any("api_fuzz" in t for t in existing_tools):
                return "API endpoint fuzzer — test common API paths and methods"

            # WebSocket found
            if "websocket" in content or "ws://" in content or "wss://" in content:
                if not any("websocket" in t for t in existing_tools):
                    return "WebSocket analyzer — connect and inspect WS endpoints"

            # S3 bucket found
            if "s3" in content or "amazonaws" in content:
                if not any("s3" in t for t in existing_tools):
                    return "S3 bucket enumerator — check for public bucket access"

            # WordPress detected but no WordPress scanner
            if "wordpress" in content or "wp-content" in content or "wp-json" in content:
                if not any("wordpress" in t for t in existing_tools):
                    return "WordPress scanner — check version, enumerate plugins, detect vulns"

            # JWT token detected but no JWT analyzer
            if "jwt" in content or "eyJ" in content and "." in content:
                if not any("jwt" in t for t in existing_tools):
                    return "JWT token analyzer — decode, check alg=none, test weak secrets"

            # Swagger/OpenAPI detected
            if "swagger" in content or "openapi" in content:
                if not any("swagger" in t for t in existing_tools):
                    return "Swagger/OpenAPI parser — enumerate endpoints from API spec"

            # Docker/container detected
            if "docker" in content and ("registry" in content or "container" in content):
                if not any("docker" in t for t in existing_tools):
                    return "Docker registry checker — test for open registries and image access"

            # Cloud provider detected
            if any(cloud in content for cloud in ["aws", "gcp", "azure", "cloudfront", "s3.amazonaws"]):
                if not any("cloud" in t for t in existing_tools):
                    return "Cloud metadata checker — test SSRF to 169.254.169.254"

            # Technology-specific: nginx/Apache version detected
            if ("nginx" in content or "apache" in content) and any(c.isdigit() for c in content):
                if not any("version_check" in t for t in existing_tools):
                    return "Version vulnerability checker — match detected versions to known CVEs"

            # .git directory exposed
            if ".git/" in url or "git/HEAD" in content:
                if not any("git_exposed" in t for t in existing_tools):
                    return "Git repository analyzer — download exposed .git and extract commit history"

            # .env file exposed
            if ".env" in url or "environment" in content and "secret" in content:
                if not any("env_checker" in t for t in existing_tools):
                    return "Environment file checker — test for exposed .env with secrets"

            # Subdomain with interesting prefix
            if any(prefix in url for prefix in ["admin.", "dev.", "staging.", "test.", "internal.", "vpn."]):
                if not any("subdomain_probe" in t for t in existing_tools):
                    return "Subdomain deep probe — test admin/dev/staging subdomains for auth bypass"

            # Form detected but no form analyzer
            if "<form" in content and "password" in content:
                if not any("form_analyzer" in t for t in existing_tools):
                    return "Form analyzer — test login forms for SQLi, default creds, auth bypass"

        return None

    async def generate_tool(self, gap: str, context: str = "", target: str = "") -> dict[str, Any]:
        """Generate a Python tool using LLM to fill a capability gap."""
        tool_id = str(uuid.uuid4())[:12]
        tool_name = self._derive_name(gap)

        logger.info(f"Generating tool for gap: {gap}")

        try:
            resp = self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self._get_model(),
                    "messages": [
                        {
                            "role": "user",
                            "content": TOOL_GEN_PROMPT.format(
                                gap=gap,
                                context=context[:500],
                                target=target,
                            ),
                        },
                    ],
                    "stream": False,
                    "options": {"temperature": 0.3, "top_p": 0.9},
                },
            )
            resp.raise_for_status()
            code = resp.json()["message"]["content"].strip()

            # Remove markdown fences if present
            if code.startswith("```"):
                code = code.split("\n", 1)[1] if "\n" in code else code[3:]
            if code.endswith("```"):
                code = code.rsplit("```", 1)[0]
            code = code.strip()

            # Save the tool
            tool_path = TOOL_LIBRARY_DIR / f"{tool_name}.py"
            tool_path.write_text(code)

            # Register the tool
            registration = {
                "id": tool_id,
                "name": tool_name,
                "gap": gap,
                "context": context[:200],
                "target": target,
                "path": str(tool_path),
                "generated_at": datetime.now().isoformat(),
                "tested": False,
                "successful": False,
            }
            with open(TOOL_REGISTRY, "a") as f:
                f.write(json.dumps(registration) + "\n")

            # Store in Neo4j
            cypher_write(
                "CREATE (m:Memory {id: $id}) "
                "SET m.memory_type = 'procedural', m.content = $content, "
                "m.target = $target, m.severity = 'info', m.timestamp = datetime(), "
                "m.tool_name = $name, m.tool_path = $path, m.gap = $gap",
                {
                    "id": tool_id,
                    "content": f"Generated tool '{tool_name}' for gap: {gap}",
                    "target": target,
                    "name": tool_name,
                    "path": str(tool_path),
                    "gap": gap,
                },
            )

            logger.info(f"Tool '{tool_name}' generated and saved to {tool_path}")
            return {
                "id": tool_id,
                "name": tool_name,
                "gap": gap,
                "path": str(tool_path),
                "code_preview": code[:500],
                "generated": True,
            }

        except Exception as e:
            logger.error(f"Tool generation failed: {e}")
            return {"error": str(e), "gap": gap, "generated": False}

    def _derive_name(self, gap: str) -> str:
        """Derive a tool name from the gap description."""
        words = gap.lower().replace("-", " ").split()
        # Take first 2-3 meaningful words
        name_parts = [w for w in words if len(w) > 2 and w not in ("the", "for", "and", "with", "that")][:3]
        return "_".join(name_parts)

    def get_tools(self) -> list[dict[str, Any]]:
        """Get all generated tools."""
        if not TOOL_REGISTRY.exists():
            return []
        tools = []
        with open(TOOL_REGISTRY, "r") as f:
            for line in f:
                try:
                    tools.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return tools

    def get_tool(self, name: str) -> dict[str, Any] | None:
        """Get a specific tool by name."""
        tools = self.get_tools()
        for t in tools:
            if t.get("name") == name:
                # Read the code
                path = Path(t.get("path", ""))
                if path.exists():
                    t["code"] = path.read_text()
                return t
        return None


tool_generator = ToolGenerator()