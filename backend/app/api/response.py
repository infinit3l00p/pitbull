"""PITBULL API — Response Engine endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.core.sentinel.response_engine import response_engine

router = APIRouter(prefix="/response", tags=["response"])


@router.get("/status")
async def get_response_status() -> dict[str, Any]:
    """Get response engine status and statistics."""
    return response_engine.get_status()


@router.get("/history")
async def get_response_history(limit: int = 20) -> dict[str, Any]:
    """Get recent response actions."""
    return {"actions": response_engine.get_history(limit)}


@router.get("/pending")
async def get_pending_approvals() -> dict[str, Any]:
    """Get actions pending human approval."""
    return {"pending": response_engine.get_pending()}


@router.post("/approve/{approval_id}")
async def approve_action(approval_id: str) -> dict[str, Any]:
    """Approve a pending destructive action."""
    return response_engine.approve_action(approval_id)


@router.post("/reject/{approval_id}")
async def reject_action(approval_id: str) -> dict[str, Any]:
    """Reject a pending destructive action."""
    return response_engine.reject_action(approval_id)


@router.get("/rules")
async def get_response_rules() -> dict[str, Any]:
    """Get the response rule mapping (attack type → actions)."""
    from app.core.sentinel.response_engine import RESPONSE_RULES, ACTION_META
    from app.core.sentinel.response_engine import ActionType
    return {
        "rules": {
            attack_type: [a.value for a in actions]
            for attack_type, actions in RESPONSE_RULES.items()
        },
        "actions": {
            a.value: {
                "level": m["level"],
                "destructive": m["destructive"],
                "reversible": m["reversible"],
                "auto": m["auto"],
            }
            for a, m in ACTION_META.items()
        },
    }