"""TrapCard — Attacker Tool Capture Engine for PITBULL.

Captures attacker tools, binaries, and session recordings from honeypot services.
Provides SSH and web upload honeypots, file capture pipeline, tool analysis with
MITRE ATT&CK mapping, and real-time SSE event streaming.
"""

from __future__ import annotations

from app.trapcard.capture import (
    capture_file,
    get_analytics,
    get_capture,
    get_session,
    init_neo4j_schema,
    list_captures,
    list_sessions,
)
from app.trapcard.analyzer import analyze_file
from app.trapcard.ssh_honeypot import ssh_honeypot, SSHHoneypot
from app.trapcard.web_honeypot import router as web_router

__all__ = [
    "capture_file",
    "analyze_file",
    "list_captures",
    "get_capture",
    "list_sessions",
    "get_session",
    "get_analytics",
    "init_neo4j_schema",
    "ssh_honeypot",
    "SSHHoneypot",
    "web_router",
]