"""PITBULL API — Suricata IDS/IPS endpoints."""

from __future__ import annotations
import logging
from typing import Any
from fastapi import APIRouter

from app.collectors.suricata import SuricataCollector

logger = logging.getLogger(__name__)

router = APIRouter(tags=["suricata"])

_collector: SuricataCollector | None = None


def _get_collector() -> SuricataCollector:
    global _collector
    if _collector is None:
        _collector = SuricataCollector()
    return _collector


def init_collector() -> SuricataCollector:
    global _collector
    if _collector is None:
        _collector = SuricataCollector()
    return _collector


@router.get("/suricata/status")
async def suricata_status() -> dict[str, Any]:
    return _get_collector().get_stats()


@router.get("/suricata/alerts")
async def suricata_alerts(limit: int = 50) -> dict[str, Any]:
    alerts = _get_collector().get_recent_alerts(limit=limit)
    return {"count": len(alerts), "alerts": alerts}


@router.get("/suricata/top-alerted")
async def suricata_top_alerted(limit: int = 20) -> dict[str, Any]:
    hosts = _get_collector().get_top_alerted_hosts(limit=limit)
    return {"count": len(hosts), "hosts": hosts}


@router.get("/suricata/rules")
async def suricata_rules(limit: int = 20) -> dict[str, Any]:
    rules = _get_collector().get_rule_summary(limit=limit)
    return {"count": len(rules), "rules": rules}