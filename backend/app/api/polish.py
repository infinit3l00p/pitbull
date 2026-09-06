"""PITBULL API — Phase 6 polish endpoints: chat, reports, ATT&CK, audit."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from app.core.chat import chat_engine
from app.core.report import report_generator
from app.core.attack import attack_framework
from app.core.audit import audit_trail

logger = logging.getLogger(__name__)

router = APIRouter(tags=["polish"])


# ── Chat Interface ──────────────────────────────────────────────────

@router.post("/chat")
async def chat(message: str) -> dict[str, Any]:
    """Send a message to PITBULL."""
    return await chat_engine.chat(message)


@router.get("/chat/history")
async def chat_history(limit: int = 50) -> dict[str, Any]:
    """Get chat history."""
    history = chat_engine.get_chat_history(limit)
    return {"messages": history, "count": len(history)}


# ── Report Generation ──────────────────────────────────────────────

@router.post("/report/generate")
async def generate_report(target: str) -> dict[str, Any]:
    """Generate a comprehensive exploration report for a target."""
    audit_trail.log_action("report_generated", target, f"Generated exploration report for {target}")
    return report_generator.generate_mission_report(target)


# ── MITRE ATT&CK ────────────────────────────────────────────────────

@router.post("/attack/load")
async def load_attack() -> dict[str, Any]:
    """Load ATT&CK techniques into Neo4j."""
    result = attack_framework.load_into_neo4j()
    audit_trail.log_action("attack_loaded", "", f"Loaded {result['loaded']} ATT&CK techniques")
    return result


@router.get("/attack/techniques")
async def get_techniques(tactic: str | None = None) -> dict[str, Any]:
    """Get ATT&CK techniques."""
    techniques = attack_framework.get_techniques(tactic)
    return {"techniques": techniques, "count": len(techniques)}


@router.get("/attack/stats")
async def attack_stats() -> dict[str, Any]:
    """Get ATT&CK framework statistics."""
    return attack_framework.get_stats()


@router.post("/attack/map")
async def map_findings(target: str) -> dict[str, Any]:
    """Map exploration findings to ATT&CK techniques."""
    result = attack_framework.map_mission_findings(target)
    audit_trail.log_action("attack_mapped", target, f"Mapped {result['techniques_mapped']} techniques for {target}")
    return result


@router.get("/attack/coverage/{target}")
async def attack_coverage(target: str) -> dict[str, Any]:
    """Get ATT&CK coverage for a target."""
    return attack_framework.get_coverage(target)


# ── Audit Trail ────────────────────────────────────────────────────

@router.get("/audit/chain")
async def get_audit_chain(limit: int = 50) -> dict[str, Any]:
    """Get the audit trail."""
    chain = audit_trail.get_chain(limit)
    return {"entries": chain, "count": len(chain)}


@router.get("/audit/verify")
async def verify_audit() -> dict[str, Any]:
    """Verify audit chain integrity."""
    return audit_trail.verify_chain()


@router.get("/audit/stats")
async def audit_stats() -> dict[str, Any]:
    """Get audit trail statistics."""
    return audit_trail.get_stats()