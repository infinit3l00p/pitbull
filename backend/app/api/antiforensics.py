"""PITBULL API — Anti-Forensics endpoints.

Endpoints for trace wiping, timestamp manipulation, ghost mode,
and post-mission sanitization.

ATT&CK Mapping: T1070 (Indicator Removal), T1562 (Impair Defenses),
T1027 (Obfuscated Files), T1620 (Reflective Code Loading)
"""

from __future__ import annotations

import os

import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.antiforensics import opsec_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["anti_forensics"])


# ── Request Models ──────────────────────────────────────────────────


class TimestompRequest(BaseModel):
    target: str = Field(..., description="File to timestomp")
    reference: str | None = Field(None, description="Reference file to copy timestamps from")


class SecureDeleteRequest(BaseModel):
    path: str = Field(..., description="File or directory to securely delete")
    passes: int = Field(3, description="Number of overwrite passes")


class HideProcessRequest(BaseModel):
    pid: int = Field(..., description="Process ID to hide")


class RenameProcessRequest(BaseModel):
    pid: int = Field(..., description="Process ID to rename")
    new_name: str | None = Field(None, description="New process name (random if omitted)")


class MemfdExecuteRequest(BaseModel):
    binary_path: str = Field(..., description="Path to binary to execute in memory")
    args: list[str] = Field(default_factory=list, description="Arguments to pass")


class SpoofMacRequest(BaseModel):
    interface: str | None = Field(None, description="Network interface (auto-detect if omitted)")


class SanitizeRequest(BaseModel):
    target: str | None = Field(None, description="Target to sanitize (all if omitted)")


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("/status")
async def antiforensics_status() -> dict[str, Any]:
    """Get anti-forensics module status."""
    return {
        "status": "ready",
        "modules": [
            "log_wiper",
            "timestamp_manipulator",
            "process_hider",
            "memory_executor",
            "network_cleaner",
            "file_wiper",
            "neo4j_cleaner",
            "opsec_manager",
        ],
        "capabilities": [
            "quick_wipe",
            "full_sanitize",
            "ghost_mode",
            "timestomp",
            "secure_delete",
            "process_hiding",
            "memfd_execute",
            "mac_spoofing",
            "tor_circuit_rotation",
            "neo4j_purge",
        ],
    }


@router.post("/ghost-mode/sync")
async def ghost_mode_sync() -> dict[str, Any]:
    """Reconcile ghost mode state after process restart.

    If the profile script exists but the in-memory flag is false,
    re-applies env vars and sets the flag. If the flag is true but
    the profile script is missing, recreates it.
    """
    return opsec_manager.ghost_mode_sync()


@router.post("/quick-wipe")
async def quick_wipe() -> dict[str, Any]:
    """Quick wipe — command history + system logs + network state."""
    return opsec_manager.quick_wipe()


@router.post("/full-sanitize")
async def full_sanitize(req: SanitizeRequest) -> dict[str, Any]:
    """Full sanitize — everything. Use after mission completion."""
    return opsec_manager.full_sanitize(target=req.target)


@router.post("/ghost-mode/enable")
async def ghost_mode_enable() -> dict[str, Any]:
    """Enable ghost mode — system-wide stealth: wipe history, clear login records,
    zero iptables counters, flush conntrack, disable history via /etc/profile.d/.

    Idempotent: safe to call when ghost mode is already partially active
    (e.g. after process restart with profile script still on disk).
    """
    return opsec_manager.ghost_mode_enable()


@router.post("/ghost-mode/disable")
async def ghost_mode_disable() -> dict[str, Any]:
    """Disable ghost mode — restore normal logging.

    Works even if the in-memory flag was lost (e.g. after restart):
    removes the profile script and restores env vars regardless.
    """
    return opsec_manager.ghost_mode_disable()


@router.get("/ghost-mode/status")
async def ghost_mode_status() -> dict[str, Any]:
    """Check if ghost mode is currently active.

    Detects state mismatches that occur after process restart:
    the profile script persists on disk while the in-memory flag resets.
    """
    profile_exists = os.path.exists("/etc/profile.d/pitbull-ghost.sh")
    mem_active = opsec_manager._ghost_active

    # Check if the running process actually has ghost env vars set
    ghost_env_active = all(
        os.environ.get(k) == v
        for k, v in {
            "HISTFILE": "/dev/null",
            "HISTSIZE": "0",
            "HISTFILESIZE": "0",
        }.items()
    )

    # Determine true state
    if mem_active and profile_exists and ghost_env_active:
        mode = "ghost"
        synced = True
    elif not mem_active and not profile_exists and not ghost_env_active:
        mode = "normal"
        synced = True
    else:
        mode = "desync"
        synced = False

    return {
        "active": mem_active,
        "profile_script": profile_exists,
        "ghost_env_vars": ghost_env_active,
        "mode": mode,
        "synced": synced,
        "warning": (
            "State mismatch detected: profile script exists on disk but "
            "in-memory flag is %s and env vars are %s. "
            "Call /ghost-mode/sync to reconcile."
            % ("set" if mem_active else "unset", "set" if ghost_env_active else "unset")
        ) if not synced else None,
    }


# ── Log Wiping ──────────────────────────────────────────────────────


@router.post("/wipe/logs")
async def wipe_logs(aggressive: bool = False) -> dict[str, Any]:
    """Wipe system logs. Aggressive mode includes journalctl + audit."""
    return opsec_manager.log_wiper.wipe_system_logs(aggressive=aggressive)


@router.post("/wipe/history")
async def wipe_history() -> dict[str, Any]:
    """Wipe command history for all users."""
    return opsec_manager.log_wiper.wipe_command_history()


@router.post("/wipe/pitbull-logs")
async def wipe_pitbull_logs() -> dict[str, Any]:
    """Wipe PITBULL application logs."""
    return opsec_manager.log_wiper.wipe_pitbull_logs()


# ── Timestamp Manipulation ──────────────────────────────────────────


@router.post("/timestomp")
async def timestomp(req: TimestompRequest) -> dict[str, Any]:
    """Copy timestamps from a reference file to target file."""
    return opsec_manager.timestamp.timestomp(req.target, req.reference)


@router.post("/timestomp/random")
async def timestomp_random(target: str) -> dict[str, Any]:
    """Set random timestamps on a file."""
    return opsec_manager.timestamp.randomize_timestamps(target)


# ── Process Hiding ──────────────────────────────────────────────────


@router.post("/process/hide")
async def hide_process(req: HideProcessRequest) -> dict[str, Any]:
    """Hide a process from ps/top/htop."""
    return opsec_manager.process.hide_process(req.pid)


@router.post("/process/unhide")
async def unhide_process(pid: int) -> dict[str, Any]:
    """Unhide a previously hidden process."""
    return opsec_manager.process.unhide_process(pid)


@router.post("/process/rename")
async def rename_process(req: RenameProcessRequest) -> dict[str, Any]:
    """Rename a process to look like a kernel thread."""
    return opsec_manager.process.rename_process(req.pid, req.new_name)


# ── Memory Execution ────────────────────────────────────────────────


@router.post("/memfd/execute")
async def memfd_execute(req: MemfdExecuteRequest) -> dict[str, Any]:
    """Execute a binary entirely in memory — no disk footprint."""
    return opsec_manager.memory.memfd_execute(req.binary_path, req.args)


# ── Network ─────────────────────────────────────────────────────────


@router.post("/network/flush-conntrack")
async def flush_conntrack() -> dict[str, Any]:
    """Flush connection tracking table."""
    return opsec_manager.network.flush_conntrack()


@router.post("/network/zero-iptables")
async def zero_iptables() -> dict[str, Any]:
    """Zero iptables packet and byte counters."""
    return opsec_manager.network.zero_iptables_counters()


@router.post("/network/spoof-mac")
async def spoof_mac(req: SpoofMacRequest) -> dict[str, Any]:
    """Spoof MAC address on a network interface."""
    return opsec_manager.network.spoof_mac(req.interface)


@router.post("/network/rotate-tor")
async def rotate_tor() -> dict[str, Any]:
    """Rotate Tor circuit (NEWNYM)."""
    return opsec_manager.network.rotate_tor_circuit()


@router.post("/network/clear-all")
async def clear_network() -> dict[str, Any]:
    """Clear all network traces."""
    return opsec_manager.network.clear_network_state()


# ── File Wiping ─────────────────────────────────────────────────────


@router.post("/file/secure-delete")
async def secure_delete(req: SecureDeleteRequest) -> dict[str, Any]:
    """Securely delete a file — overwrite then remove."""
    return opsec_manager.file_wiper.secure_delete(req.path, req.passes)


@router.post("/file/wipe-free-space")
async def wipe_free_space(path: str = "/") -> dict[str, Any]:
    """Overwrite free disk space to prevent recovery."""
    return opsec_manager.file_wiper.wipe_free_space(path)


# ── Neo4j Purge ─────────────────────────────────────────────────────


@router.post("/neo4j/purge-episodic")
async def purge_episodic(target: str | None = None) -> dict[str, Any]:
    """Purge episodic memories from Neo4j."""
    return opsec_manager.neo4j.purge_episodic_memory(target)


@router.post("/neo4j/purge-exploits")
async def purge_exploits(target: str | None = None) -> dict[str, Any]:
    """Purge exploit attempt records."""
    return opsec_manager.neo4j.purge_exploit_attempts(target)


@router.post("/neo4j/purge-missions")
async def purge_missions() -> dict[str, Any]:
    """Purge mission history."""
    return opsec_manager.neo4j.purge_mission_history()


@router.post("/neo4j/purge-opinions")
async def purge_opinions(target: str | None = None) -> dict[str, Any]:
    """Purge PITBULL opinions."""
    return opsec_manager.neo4j.purge_opinions(target)


@router.post("/neo4j/purge-semantic-rules")
async def purge_semantic_rules() -> dict[str, Any]:
    """Purge learned semantic rules."""
    return opsec_manager.neo4j.purge_semantic_rules()


@router.post("/neo4j/full-wipe")
async def full_db_wipe() -> dict[str, Any]:
    """⚠️ Delete ALL data from Neo4j. Use with extreme caution."""
    return opsec_manager.neo4j.full_database_wipe()