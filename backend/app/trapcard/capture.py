"""TrapCard Capture Pipeline — saves attacker-uploaded files and records metadata.

Creates directory structure under /opt/pitbull/captured_tools/{service}/{YYYY-MM-DD}/{session_id}/
Saves uploaded file + metadata.json with SHA256, size, MIME type, source IP, timestamp.
Stores :ToolSample and :AttackerSession nodes in Neo4j.
"""

from __future__ import annotations

import hashlib
import json
import logging
import mimetypes
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)

CAPTURE_BASE = Path("/opt/pitbull/captured_tools")


def _ensure_base_dir() -> None:
    """Ensure the capture base directory exists."""
    CAPTURE_BASE.mkdir(parents=True, exist_ok=True)


def _sha256(data: bytes) -> str:
    """Compute SHA256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def _guess_mime(filename: str, data: bytes) -> str:
    """Guess MIME type from filename and magic bytes."""
    mime, _ = mimetypes.guess_type(filename)
    if mime:
        return mime

    # Magic byte detection
    if len(data) >= 4:
        magic = data[:4]
        if magic[:4] == b"\x7fELF":
            return "application/x-elf"
        if magic[:2] == b"MZ":
            return "application/x-dosexec"
        if magic[:4] == b"\xcf\xfa\xed\xfe":
            return "application/x-mach-binary"
        if magic[:2] == b"#!":
            return "text/x-shellscript"
        if magic[:2] == b"PK":
            return "application/zip"
        if magic[:3] == b"GIF":
            return "image/gif"
        if magic[:4] == b"\x89PNG":
            return "image/png"
        if magic[:3] == b"\xff\xd8\xff":
            return "image/jpeg"

    # Try UTF-8 decode for text
    try:
        data.decode("utf-8")
        return "text/plain"
    except (UnicodeDecodeError, Exception):
        pass

    return "application/octet-stream"


def capture_file(
    file_data: bytes,
    source_ip: str,
    service: str,
    session_id: str,
    filename: str | None = None,
) -> dict[str, Any]:
    """Capture an attacker-uploaded file.

    Args:
        file_data: Raw file bytes.
        source_ip: Attacker IP address.
        service: Honeypot service name (e.g. 'ssh', 'web').
        session_id: Attacker session identifier.
        filename: Original filename if known.

    Returns:
        Metadata dict with sha256, size, mime_type, file_path, etc.
    """
    _ensure_base_dir()

    # Generate IDs
    sha256 = _sha256(file_data)
    size = len(file_data)
    mime_type = _guess_mime(filename or "", file_data)
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    timestamp = now.isoformat()
    capture_id = str(uuid.uuid4())

    # Determine filename
    if not filename:
        filename = f"capture_{sha256[:12]}"

    # Create directory structure
    capture_dir = CAPTURE_BASE / service / date_str / session_id
    capture_dir.mkdir(parents=True, exist_ok=True)

    # Save file
    file_path = capture_dir / filename
    # Avoid collisions
    if file_path.exists():
        file_path = capture_dir / f"{filename}_{sha256[:8]}"
    file_path.write_bytes(file_data)

    # Build metadata
    metadata: dict[str, Any] = {
        "capture_id": capture_id,
        "sha256": sha256,
        "size": size,
        "mime_type": mime_type,
        "filename": filename,
        "source_ip": source_ip,
        "service": service,
        "session_id": session_id,
        "timestamp": timestamp,
        "file_path": str(file_path),
    }

    # Save metadata.json alongside the file
    meta_path = capture_dir / "metadata.json"
    # Merge with existing metadata if present (multiple files per session)
    existing_meta: dict[str, Any] = {}
    if meta_path.exists():
        try:
            existing_meta = json.loads(meta_path.read_text())
            if "files" not in existing_meta:
                existing_meta = {"files": [existing_meta] if existing_meta else []}
        except Exception:
            existing_meta = {"files": []}

    if "files" not in existing_meta:
        existing_meta["files"] = []

    existing_meta["files"].append(metadata)
    existing_meta["session_id"] = session_id
    existing_meta["source_ip"] = source_ip
    existing_meta["service"] = service
    meta_path.write_text(json.dumps(existing_meta, indent=2))

    # Store in Neo4j
    try:
        cypher_write(
            """
            MERGE (t:ToolSample {sha256: $sha256})
            SET t.size = $size,
                t.mime_type = $mime_type,
                t.filename = $filename,
                t.service = $service,
                t.captured_at = $timestamp,
                t.file_path = $file_path,
                t.capture_id = $capture_id
            """,
            {
                "sha256": sha256,
                "size": size,
                "mime_type": mime_type,
                "filename": filename,
                "service": service,
                "timestamp": timestamp,
                "file_path": str(file_path),
                "capture_id": capture_id,
            },
        )

        # Create or merge AttackerSession and link to ToolSample
        cypher_write(
            """
            MERGE (s:AttackerSession {session_id: $session_id})
            SET s.source_ip = $source_ip,
                s.service = $service,
                s.last_seen = $timestamp,
                s.updated_at = $timestamp
            WITH s
            MATCH (t:ToolSample {sha256: $sha256})
            MERGE (s)-[:UPLOADED]->(t)
            """,
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "service": service,
                "timestamp": timestamp,
                "sha256": sha256,
            },
        )

        # Link AttackerSession to Attacker IP node (if Sentinel created one)
        cypher_write(
            """
            MERGE (s:AttackerSession {session_id: $session_id})
            MERGE (a:Attacker {ip: $source_ip})
            MERGE (a)-[:HAS_SESSION]->(s)
            """,
            {
                "session_id": session_id,
                "source_ip": source_ip,
            },
        )

        logger.info(
            "TrapCard: captured file %s (sha256=%s, size=%d, service=%s, ip=%s)",
            filename, sha256[:16], size, service, source_ip,
        )
    except Exception as e:
        logger.error("TrapCard: Neo4j store error: %s", e)

    return metadata


def list_captures(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List all captured tool samples from Neo4j."""
    try:
        results = cypher_read(
            """
            MATCH (t:ToolSample)
            OPTIONAL MATCH (s:AttackerSession)-[:UPLOADED]->(t)
            RETURN t, s
            ORDER BY t.captured_at DESC
            SKIP $offset LIMIT $limit
            """,
            {"limit": limit, "offset": offset},
        )
        captures = []
        for row in results:
            t = row.get("t", {})
            s = row.get("s", {})
            captures.append({
                "capture_id": t.get("capture_id"),
                "sha256": t.get("sha256"),
                "size": t.get("size"),
                "mime_type": t.get("mime_type"),
                "filename": t.get("filename"),
                "service": t.get("service"),
                "captured_at": t.get("captured_at"),
                "file_path": t.get("file_path"),
                "source_ip": s.get("source_ip"),
                "session_id": s.get("session_id"),
                "attack_techniques": t.get("attack_techniques", []),
                "analysis": t.get("analysis"),
            })
        return {"captures": captures, "count": len(captures)}
    except Exception as e:
        logger.error("TrapCard: list_captures error: %s", e)
        return {"captures": [], "count": 0}


def get_capture(capture_id: str) -> dict[str, Any] | None:
    """Get a specific capture by capture_id."""
    try:
        results = cypher_read(
            """
            MATCH (t:ToolSample {capture_id: $capture_id})
            OPTIONAL MATCH (s:AttackerSession)-[:UPLOADED]->(t)
            RETURN t, s
            LIMIT 1
            """,
            {"capture_id": capture_id},
        )
        if not results:
            return None
        row = results[0]
        t = row.get("t", {})
        s = row.get("s", {})
        return {
            "capture_id": t.get("capture_id"),
            "sha256": t.get("sha256"),
            "size": t.get("size"),
            "mime_type": t.get("mime_type"),
            "filename": t.get("filename"),
            "service": t.get("service"),
            "captured_at": t.get("captured_at"),
            "file_path": t.get("file_path"),
            "source_ip": s.get("source_ip"),
            "session_id": s.get("session_id"),
            "attack_techniques": t.get("attack_techniques", []),
            "analysis": t.get("analysis"),
        }
    except Exception as e:
        logger.error("TrapCard: get_capture error: %s", e)
        return None


def list_sessions(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List all attacker sessions from Neo4j."""
    try:
        results = cypher_read(
            """
            MATCH (s:AttackerSession)
            OPTIONAL MATCH (s)-[:UPLOADED]->(t:ToolSample)
            WITH s, collect(t) AS tools
            RETURN s, tools
            ORDER BY s.last_seen DESC
            SKIP $offset LIMIT $limit
            """,
            {"limit": limit, "offset": offset},
        )
        sessions = []
        for row in results:
            s = row.get("s", {})
            tools = row.get("tools", [])
            sessions.append({
                "session_id": s.get("session_id"),
                "source_ip": s.get("source_ip"),
                "service": s.get("service"),
                "first_seen": s.get("first_seen"),
                "last_seen": s.get("last_seen"),
                "log_path": s.get("log_path"),
                "tool_count": len(tools),
                "tools": [
                    {
                        "sha256": t.get("sha256"),
                        "filename": t.get("filename"),
                        "size": t.get("size"),
                        "mime_type": t.get("mime_type"),
                    }
                    for t in tools
                ],
            })
        return {"sessions": sessions, "count": len(sessions)}
    except Exception as e:
        logger.error("TrapCard: list_sessions error: %s", e)
        return {"sessions": [], "count": 0}


def get_session(session_id: str) -> dict[str, Any] | None:
    """Get a specific session by session_id, including recording."""
    try:
        results = cypher_read(
            """
            MATCH (s:AttackerSession {session_id: $session_id})
            OPTIONAL MATCH (s)-[:UPLOADED]->(t:ToolSample)
            WITH s, collect(t) AS tools
            RETURN s, tools
            LIMIT 1
            """,
            {"session_id": session_id},
        )
        if not results:
            return None
        row = results[0]
        s = row.get("s", {})
        tools = row.get("tools", [])

        # Read session log if available
        recording = None
        log_path = s.get("log_path")
        if log_path and os.path.exists(log_path):
            try:
                recording = Path(log_path).read_text(errors="replace")
            except Exception as e:
                recording = f"[Error reading log: {e}]"

        return {
            "session_id": s.get("session_id"),
            "source_ip": s.get("source_ip"),
            "service": s.get("service"),
            "first_seen": s.get("first_seen"),
            "last_seen": s.get("last_seen"),
            "log_path": s.get("log_path"),
            "recording": recording,
            "tool_count": len(tools),
            "tools": [
                {
                    "sha256": t.get("sha256"),
                    "filename": t.get("filename"),
                    "size": t.get("size"),
                    "mime_type": t.get("mime_type"),
                    "capture_id": t.get("capture_id"),
                    "attack_techniques": t.get("attack_techniques", []),
                }
                for t in tools
            ],
        }
    except Exception as e:
        logger.error("TrapCard: get_session error: %s", e)
        return None


def get_analytics() -> dict[str, Any]:
    """Get capture analytics: by type, by IP, by day, ATT&CK mapping."""
    try:
        # By MIME type
        by_type = cypher_read(
            """
            MATCH (t:ToolSample)
            RETURN t.mime_type AS type, count(*) AS count
            ORDER BY count DESC
            """
        )

        # By source IP
        by_ip = cypher_read(
            """
            MATCH (s:AttackerSession)-[:UPLOADED]->(t:ToolSample)
            RETURN s.source_ip AS ip, count(t) AS count
            ORDER BY count DESC
            LIMIT 20
            """
        )

        # By day
        by_day = cypher_read(
            """
            MATCH (t:ToolSample)
            RETURN substring(t.captured_at, 0, 10) AS day, count(*) AS count
            ORDER BY day DESC
            LIMIT 30
            """
        )

        # ATT&CK techniques
        attack_mapping = cypher_read(
            """
            MATCH (t:ToolSample)
            UNWIND t.attack_techniques AS technique
            RETURN technique, count(*) AS count
            ORDER BY count DESC
            """
        )

        # Totals
        totals = cypher_read(
            """
            MATCH (t:ToolSample)
            WITH count(t) AS total_captures
            OPTIONAL MATCH (s:AttackerSession)
            WITH total_captures, count(s) AS total_sessions
            OPTIONAL MATCH (a:Attacker)
            RETURN total_captures, total_sessions, count(a) AS total_attackers
            """
        )

        total_data = totals[0] if totals else {}

        return {
            "total_captures": total_data.get("total_captures", 0),
            "total_sessions": total_data.get("total_sessions", 0),
            "total_attackers": total_data.get("total_attackers", 0),
            "by_type": [{"type": r["type"], "count": r["count"]} for r in by_type],
            "by_ip": [{"ip": r["ip"], "count": r["count"]} for r in by_ip],
            "by_day": [{"day": r["day"], "count": r["count"]} for r in by_day],
            "attack_mapping": [{"technique": r["technique"], "count": r["count"]} for r in attack_mapping],
        }
    except Exception as e:
        logger.error("TrapCard: analytics error: %s", e)
        return {
            "total_captures": 0,
            "total_sessions": 0,
            "total_attackers": 0,
            "by_type": [],
            "by_ip": [],
            "by_day": [],
            "attack_mapping": [],
        }


def init_neo4j_schema() -> None:
    """Initialize TrapCard-specific Neo4j constraints and indexes."""
    constraints = [
        "CREATE CONSTRAINT tool_sample_sha256 IF NOT EXISTS FOR (t:ToolSample) REQUIRE t.sha256 IS UNIQUE",
        "CREATE CONSTRAINT attacker_session_id IF NOT EXISTS FOR (s:AttackerSession) REQUIRE s.session_id IS UNIQUE",
    ]
    indexes = [
        "CREATE INDEX tool_sample_service IF NOT EXISTS FOR (t:ToolSample) ON (t.service)",
        "CREATE INDEX tool_sample_captured IF NOT EXISTS FOR (t:ToolSample) ON (t.captured_at)",
        "CREATE INDEX attacker_session_ip IF NOT EXISTS FOR (s:AttackerSession) ON (s.source_ip)",
        "CREATE INDEX attacker_session_service IF NOT EXISTS FOR (s:AttackerSession) ON (s.service)",
    ]
    try:
        for stmt in constraints:
            try:
                cypher_write(stmt)
            except Exception as e:
                logger.debug("TrapCard: constraint skipped: %s", e)
        for stmt in indexes:
            try:
                cypher_write(stmt)
            except Exception as e:
                logger.debug("TrapCard: index skipped: %s", e)
        logger.info("TrapCard: Neo4j schema initialized")
    except Exception as e:
        logger.error("TrapCard: Neo4j schema init error: %s", e)