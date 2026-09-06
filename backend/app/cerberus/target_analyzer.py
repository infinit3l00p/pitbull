"""Cerberus Target Analyzer — identifies and profiles fuzzing targets.

Analyzes binaries (ELF, PE, Mach-O), network protocols, and REST APIs
to extract input vectors and build a structured target profile. Uses LLM
to understand target structure and suggest attack surface.

Academic basis:
- LLAMAFUZZ (arXiv:2406.07714): target-aware fuzzing guidance
- ELFuzz (arXiv:2506.10323): meta-level target understanding
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import struct
import subprocess
from datetime import datetime
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


class TargetAnalyzer:
    """Analyze fuzzing targets and extract input vectors."""

    def __init__(self) -> None:
        self.base_url = settings.llm_base_url
        self.primary_model = settings.llm_model
        self.local_model = "qwen2.5:7b"
        self._local_available: bool | None = None
        self.client = httpx.Client(timeout=60.0)

    # ── LLM helpers (same pattern as exploit_experts.py) ────────────

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
                    "options": {"temperature": 0.4, "top_p": 0.9},
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
                            "options": {"temperature": 0.4, "top_p": 0.9},
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

    # ── Binary analysis ─────────────────────────────────────────────

    def analyze_binary(self, file_path: str) -> dict[str, Any]:
        """Analyze a binary file to determine type, architecture, and input vectors.

        Uses file header parsing (ELF, PE, Mach-O) and the `file` command as fallback.
        """
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        result: dict[str, Any] = {
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "analyzed_at": datetime.now().isoformat(),
        }

        # Read first 512 bytes for header
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)
        except OSError as e:
            return {"error": f"Cannot read file: {e}", "file_path": file_path}

        # Determine binary type from magic bytes
        binary_type = self._identify_binary_type(header)
        result.update(binary_type)

        # Use `file` command for additional info
        try:
            file_out = subprocess.run(
                ["file", "-b", file_path],
                capture_output=True, text=True, timeout=10,
            )
            if file_out.returncode == 0:
                result["file_command"] = file_out.stdout.strip()
        except Exception:
            pass

        # Extract linked libraries
        result["linked_libraries"] = self._extract_libraries(file_path, result.get("binary_type", "unknown"))

        # Extract entry points / symbols
        result["entry_points"] = self._extract_entry_points(file_path, result.get("binary_type", "unknown"))

        # Determine input vectors
        result["input_vectors"] = self._binary_input_vectors(result)

        # LLM analysis of attack surface
        llm_analysis = self._llm_binary_analysis(result)
        if "error" not in llm_analysis:
            result["llm_analysis"] = llm_analysis

        return result

    def _identify_binary_type(self, header: bytes) -> dict[str, Any]:
        """Identify binary type from magic bytes."""
        info: dict[str, Any] = {}

        if len(header) < 4:
            return {"binary_type": "unknown", "error": "File too small"}

        # ELF magic: \x7fELF
        if header[:4] == b"\x7fELF":
            info["binary_type"] = "ELF"
            if len(header) >= 20:
                ei_class = header[4]
                info["bits"] = 32 if ei_class == 1 else 64 if ei_class == 2 else 0
                ei_data = header[5]
                info["endian"] = "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown"
                # e_machine at offset 18 (2 bytes)
                machine = struct.unpack_from("<H", header, 18)[0] if ei_data == 1 else struct.unpack_from(">H", header, 18)[0]
                arch_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64", 0xF3: "RISC-V", 0x15: "PPC64"}
                info["architecture"] = arch_map.get(machine, f"unknown(0x{machine:x})")
                # ELF type at offset 16
                e_type = struct.unpack_from("<H", header, 16)[0] if ei_data == 1 else struct.unpack_from(">H", header, 16)[0]
                type_map = {1: "REL", 2: "EXEC", 3: "DYN (shared library / PIE)", 4: "CORE"}
                info["elf_type"] = type_map.get(e_type, f"unknown(0x{e_type:x})")

        # PE/COFF magic: "MZ"
        elif header[:2] == b"MZ":
            info["binary_type"] = "PE"
            info["architecture"] = "x86/x86_64"
            # PE header offset at 0x3C
            if len(header) >= 64:
                pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
                if pe_offset + 6 <= len(header):
                    machine = struct.unpack_from("<H", header, pe_offset + 4)[0]
                    arch_map = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "AArch64"}
                    info["architecture"] = arch_map.get(machine, f"unknown(0x{machine:x})")

        # Mach-O magic
        elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            info["binary_type"] = "Mach-O"
            magic = header[:4]
            if magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
                info["bits"] = 32
            else:
                info["bits"] = 64
            if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                info["endian"] = "little"
            else:
                info["endian"] = "big"
            # CPU type at offset 4
            if len(header) >= 8:
                cpu_type = struct.unpack_from("<I", header, 4)[0] if info.get("endian") == "little" else struct.unpack_from(">I", header, 4)[0]
                cpu_map = {7: "x86", 0x1000007: "x86_64", 12: "ARM", 0x100000C: "AArch64"}
                info["architecture"] = cpu_map.get(cpu_type, f"unknown(0x{cpu_type:x})")

        # Java class file
        elif header[:4] == b"\xca\xfe\xba\xbe":
            info["binary_type"] = "Java class"

        # Python pyc
        elif header[:2] in (b"\x42\x0d", b"\x42\x0e", b"\x42\x0f"):
            info["binary_type"] = "Python bytecode"

        # Script (shebang)
        elif header[:2] == b"#!":
            info["binary_type"] = "script"
            try:
                shebang_line = header.split(b"\n")[0].decode("utf-8", errors="replace")
                info["interpreter"] = shebang_line[2:].strip()
            except Exception:
                pass

        else:
            info["binary_type"] = "unknown"

        return info

    def _extract_libraries(self, file_path: str, binary_type: str) -> list[str]:
        """Extract linked libraries using system tools."""
        libs: list[str] = []
        try:
            if binary_type == "ELF":
                out = subprocess.run(
                    ["readelf", "-d", file_path],
                    capture_output=True, text=True, timeout=10,
                )
                if out.returncode == 0:
                    for line in out.stdout.splitlines():
                        if "NEEDED" in line:
                            match = re.search(r"\[(.+?)\]", line)
                            if match:
                                libs.append(match.group(1))
            elif binary_type == "PE":
                out = subprocess.run(
                    ["objdump", "-p", file_path],
                    capture_output=True, text=True, timeout=10,
                )
                if out.returncode == 0:
                    for line in out.stdout.splitlines():
                        if "DLL Name" in line:
                            match = re.search(r"DLL Name:\s*(.+)", line)
                            if match:
                                libs.append(match.group(1).strip())
            elif binary_type == "Mach-O":
                out = subprocess.run(
                    ["otool", "-L", file_path],
                    capture_output=True, text=True, timeout=10,
                )
                if out.returncode == 0:
                    for line in out.stdout.splitlines()[1:]:  # skip first line (binary name)
                        lib = line.strip().split(" ")[0] if line.strip() else ""
                        if lib:
                            libs.append(lib)
        except Exception as e:
            logger.debug(f"Library extraction failed: {e}")
        return libs

    def _extract_entry_points(self, file_path: str, binary_type: str) -> list[str]:
        """Extract entry point symbols."""
        entries: list[str] = []
        try:
            if binary_type == "ELF":
                out = subprocess.run(
                    ["readelf", "-h", file_path],
                    capture_output=True, text=True, timeout=10,
                )
                if out.returncode == 0:
                    for line in out.stdout.splitlines():
                        if "Entry point address" in line:
                            match = re.search(r"0x[0-9a-fA-F]+", line)
                            if match:
                                entries.append(f"entry: {match.group()}")
                # Also get exported symbols
                out2 = subprocess.run(
                    ["nm", "-D", file_path],
                    capture_output=True, text=True, timeout=10,
                )
                if out2.returncode == 0:
                    for line in out2.stdout.splitlines()[:20]:
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] in ("T", "W"):
                            entries.append(parts[2])
            elif binary_type in ("PE", "Mach-O"):
                out = subprocess.run(
                    ["nm", file_path],
                    capture_output=True, text=True, timeout=10,
                )
                if out.returncode == 0:
                    for line in out.stdout.splitlines()[:20]:
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] in ("T", "t", "W", "w"):
                            entries.append(parts[2])
        except Exception as e:
            logger.debug(f"Entry point extraction failed: {e}")
        return entries

    def _binary_input_vectors(self, info: dict[str, Any]) -> list[dict[str, Any]]:
        """Determine input vectors for a binary target."""
        vectors: list[dict[str, Any]] = []
        btype = info.get("binary_type", "unknown")

        if btype in ("ELF", "PE", "Mach-O"):
            vectors.append({"type": "cli_args", "description": "Command-line arguments"})
            vectors.append({"type": "stdin", "description": "Standard input"})
            vectors.append({"type": "env_vars", "description": "Environment variables"})
            vectors.append({"type": "file_input", "description": "File input (if program reads files)"})
            vectors.append({"type": "network", "description": "Network input (if program listens on sockets)"})
        elif btype == "script":
            vectors.append({"type": "cli_args", "description": "Command-line arguments"})
            vectors.append({"type": "stdin", "description": "Standard input"})
            vectors.append({"type": "env_vars", "description": "Environment variables"})
        elif btype == "Java class":
            vectors.append({"type": "cli_args", "description": "Command-line arguments"})
            vectors.append({"type": "stdin", "description": "Standard input"})

        return vectors

    def _llm_binary_analysis(self, info: dict[str, Any]) -> dict[str, Any]:
        """Use LLM to analyze binary attack surface."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You analyze binary targets to identify attack surface and suggest "
            "fuzzing strategies. Respond in JSON only."
        )
        prompt = f"""Analyze this binary target and suggest fuzzing strategies:

Target info:
{json.dumps(info, ensure_ascii=False, default=str)[:2000]}

Respond as JSON:
{{
  "attack_surface": ["list of likely input vectors"],
  "suggested_strategies": ["mutation", "grammar", "semantic", "path-guided"],
  "priority_inputs": ["which inputs to fuzz first"],
  "expected_formats": ["what input formats the target likely expects"],
  "risk_areas": ["potential vulnerability areas based on binary type"],
  "recommended_seed_inputs": ["suggested seed inputs for fuzzing"]
}}"""
        return self._call_llm(system, prompt)

    # ── Protocol analysis ───────────────────────────────────────────

    async def analyze_protocol(self, port: int, host: str = "127.0.0.1") -> dict[str, Any]:
        """Analyze a network protocol by sending probes."""
        result: dict[str, Any] = {
            "host": host,
            "port": port,
            "analyzed_at": datetime.now().isoformat(),
        }

        # Common protocol probes
        probes = [
            (b"GET / HTTP/1.0\r\n\r\n", "HTTP"),
            (b"220\r\n", "FTP"),
            (b"EHLO localhost\r\n", "SMTP"),
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", "binary"),
            (b"PING\r\n", "Redis"),
            (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x00\x00", "RDP"),
        ]

        async with httpx.AsyncClient(timeout=10.0) as client:
            for probe_data, proto_name in probes:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=5.0
                    )
                    writer.write(probe_data)
                    await writer.drain()
                    response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                    writer.close()
                    await writer.wait_closed()

                    if response:
                        result["detected_protocol"] = proto_name
                        result["banner"] = response[:256].decode("utf-8", errors="replace")
                        result["probe_used"] = proto_name
                        break
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    continue

        # LLM analysis if we got a response
        if "detected_protocol" in result:
            llm_result = self._llm_protocol_analysis(result)
            if "error" not in llm_result:
                result["llm_analysis"] = llm_result

        # Input vectors for protocol targets
        result["input_vectors"] = [
            {"type": "network", "description": f"TCP/{port} protocol data"},
            {"type": "malformed_packets", "description": "Malformed protocol packets"},
            {"type": "oversized_input", "description": "Oversized protocol messages"},
            {"type": "encoding_variants", "description": "Different encoding of protocol data"},
        ]

        return result

    def _llm_protocol_analysis(self, info: dict[str, Any]) -> dict[str, Any]:
        """Use LLM to analyze protocol attack surface."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You analyze network protocols to identify fuzzing vectors. "
            "Respond in JSON only."
        )
        prompt = f"""Analyze this network protocol target:

{json.dumps(info, ensure_ascii=False, default=str)[:1500]}

Respond as JSON:
{{
  "protocol_guess": "best guess for the protocol",
  "attack_surface": ["list of protocol-specific attack vectors"],
  "suggested_strategies": ["mutation", "grammar", "semantic"],
  "grammar_elements": ["protocol grammar elements to fuzz"],
  "recommended_seed_inputs": ["suggested seed inputs as base64"],
  "risk_areas": ["potential vulnerability areas"]
}}"""
        return self._call_llm(system, prompt)

    # ── API analysis ────────────────────────────────────────────────

    async def analyze_api(self, base_url: str) -> dict[str, Any]:
        """Discover API endpoints, parameters, and methods."""
        result: dict[str, Any] = {
            "base_url": base_url,
            "analyzed_at": datetime.now().isoformat(),
            "endpoints": [],
        }

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            # Try common discovery endpoints
            discovery_paths = [
                "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
                "/openapi.json", "/openapi/v1", "/.well-known/openapi",
                "/api/v1/", "/api/", "/docs", "/redoc",
                "/health", "/status", "/metrics",
            ]

            for path in discovery_paths:
                try:
                    resp = await client.get(f"{base_url.rstrip('/')}{path}")
                    if resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "")
                        body = resp.text[:2000]
                        if "json" in content_type or path.endswith(".json"):
                            try:
                                data = resp.json()
                                if "paths" in data:  # OpenAPI/Swagger
                                    result["openapi_spec"] = True
                                    result["endpoints"] = self._parse_openapi(data)
                                    result["api_spec_url"] = f"{base_url.rstrip('/')}{path}"
                                    break
                            except json.JSONDecodeError:
                                pass
                        result["endpoints"].append({
                            "path": path,
                            "method": "GET",
                            "status": resp.status_code,
                            "content_type": content_type,
                            "body_preview": body[:200],
                        })
                except (httpx.HTTPError, asyncio.TimeoutError):
                    continue

            # Probe common REST endpoints
            common_endpoints = [
                ("/users", ["GET", "POST"]),
                ("/api/users", ["GET", "POST"]),
                ("/api/v1/users", ["GET", "POST"]),
                ("/login", ["POST"]),
                ("/auth", ["POST"]),
                ("/register", ["POST"]),
                ("/search", ["GET"]),
                ("/upload", ["POST"]),
                ("/admin", ["GET"]),
                ("/config", ["GET"]),
            ]

            for path, methods in common_endpoints:
                for method in methods:
                    try:
                        resp = await client.request(method, f"{base_url.rstrip('/')}{path}")
                        if resp.status_code not in (404, 405):
                            result["endpoints"].append({
                                "path": path,
                                "method": method,
                                "status": resp.status_code,
                                "content_type": resp.headers.get("content-type", ""),
                                "body_preview": resp.text[:200],
                            })
                    except (httpx.HTTPError, asyncio.TimeoutError):
                        continue

        # Input vectors for API targets
        result["input_vectors"] = self._api_input_vectors(result)

        # LLM analysis
        llm_result = self._llm_api_analysis(result)
        if "error" not in llm_result:
            result["llm_analysis"] = llm_result

        return result

    def _parse_openapi(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse OpenAPI spec to extract endpoints."""
        endpoints: list[dict[str, Any]] = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    params = details.get("parameters", [])
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "parameters": [
                            {"name": p.get("name"), "in": p.get("in"), "required": p.get("required", False),
                             "type": p.get("schema", {}).get("type", "string")}
                            for p in params
                        ],
                        "request_body": "requestBody" in details,
                    })
        return endpoints

    def _api_input_vectors(self, info: dict[str, Any]) -> list[dict[str, Any]]:
        """Determine input vectors for an API target."""
        vectors: list[dict[str, Any]] = [
            {"type": "query_params", "description": "URL query parameters"},
            {"type": "body_params", "description": "Request body parameters (JSON/form)"},
            {"type": "headers", "description": "HTTP headers"},
            {"type": "path_params", "description": "URL path parameters"},
            {"type": "cookies", "description": "Cookie values"},
            {"type": "method_override", "description": "HTTP method override headers"},
        ]

        # Add specific endpoints from discovery
        for ep in info.get("endpoints", []):
            if isinstance(ep, dict) and ep.get("parameters"):
                for param in ep["parameters"]:
                    vectors.append({
                        "type": f"param:{param.get('name', 'unknown')}",
                        "description": f"Parameter '{param.get('name')}' in {param.get('in', 'unknown')} for {ep.get('path')}",
                    })

        return vectors

    def _llm_api_analysis(self, info: dict[str, Any]) -> dict[str, Any]:
        """Use LLM to analyze API attack surface."""
        system = (
            "You are PITBULL-Cerberus, an autonomous security fuzzer. "
            "You analyze REST APIs to identify fuzzing vectors. "
            "Respond in JSON only."
        )
        prompt = f"""Analyze this API target:

{json.dumps(info, ensure_ascii=False, default=str)[:2000]}

Respond as JSON:
{{
  "api_type": "REST/GraphQL/gRPC/other",
  "attack_surface": ["list of API-specific attack vectors"],
  "suggested_strategies": ["mutation", "grammar", "semantic"],
  "priority_endpoints": ["which endpoints to fuzz first"],
  "recommended_seed_inputs": ["suggested seed inputs for API fuzzing"],
  "risk_areas": ["potential vulnerability areas"],
  "auth_bypass_vectors": ["authentication/authorization test vectors"]
}}"""
        return self._call_llm(system, prompt)

    # ── Input vector extraction ─────────────────────────────────────

    def extract_input_vectors(self, target_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract all input vectors from a target profile."""
        return target_info.get("input_vectors", [])

    # ── Unified analyze ─────────────────────────────────────────────

    async def analyze(self, target: str, target_type: str) -> dict[str, Any]:
        """Unified analysis entry point.

        Args:
            target: Binary path, URL, or host:port
            target_type: "binary", "protocol", or "api"
        """
        if target_type == "binary":
            return self.analyze_binary(target)
        elif target_type == "protocol":
            parts = target.split(":")
            host = parts[0] if len(parts) > 1 else "127.0.0.1"
            port = int(parts[1]) if len(parts) > 1 else int(parts[0])
            return await self.analyze_protocol(port, host)
        elif target_type == "api":
            return await self.analyze_api(target)
        else:
            return {"error": f"Unknown target type: {target_type}"}