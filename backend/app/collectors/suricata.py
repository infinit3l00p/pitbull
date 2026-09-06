"""Suricata collector — IDS/IPS alert ingestion from EVE JSON.

Reads Suricata's eve.json in real-time and feeds alerts + stats into PITBULL's
Neo4j graph and Sentinel attack detection engine.

Suricata EVE JSON: https://docs.suricata.io/en/latest/output/eve/eve-json-output.html

Data collected:
- Alert events (signature, severity, source/dest IP, protocol, action)
- Stats events (packet counts, drop counts, alert counts)
- Flow events (TCP/UDP/ICMP flow data)
- HTTP events (URLs, user agents)
- DNS events (queries, answers)
- TLS events (certificates, SNI)

Graph model:
  (:SuricataAlert {id}) -[:CONCERNS]-> (:Host {ip})
  (:Host {ip}) -[:SURICATA_ALERTED {count}]-> (:Host {ip})
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import os
from typing import Any

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)

EVE_JSON_PATH = "/var/log/suricata/eve.json"
POLL_INTERVAL = 5  # seconds between reads
MAX_EVENTS_PER_POLL = 500


class SuricataCollector:
    """Reads Suricata EVE JSON events and feeds them into PITBULL."""

    def __init__(self, on_alert_callback=None):
        self._running = False
        self._file_handle = None
        self._offset = 0
        self._total_alerts = 0
        self._total_flows = 0
        self._total_http = 0
        self._total_dns = 0
        self._total_tls = 0
        self._total_stats = 0
        self._total_drops = 0
        self._last_stats = {}
        self._on_alert = on_alert_callback
        self._seen_alert_ids = set()

    def _init_neo4j_schema(self) -> bool:
        """Initialize Neo4j constraints for Suricata data. Returns False if Neo4j unavailable."""
        try:
            cypher_write("CREATE CONSTRAINT suricata_alert_id IF NOT EXISTS FOR (a:SuricataAlert) REQUIRE a.id IS UNIQUE")
            cypher_write("CREATE CONSTRAINT suricata_rule_id IF NOT EXISTS FOR (r:SuricataRule) REQUIRE r.signature_id IS UNIQUE")
            logger.info("suricata: Neo4j schema initialized")
            return True
        except Exception as e:
            logger.warning(f"suricata: Neo4j not ready, skipping schema init: {e}")
            return False

    def _store_alert(self, event: dict[str, Any]) -> None:
        """Store a Suricata alert event in Neo4j."""
        if not getattr(self, '_neo4j_ready', False):
            return
        alert = event.get("alert", {})
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dest_ip", "")
        proto = event.get("proto", "unknown")
        sig_id = alert.get("signature_id", 0)
        signature = alert.get("signature", "unknown")
        category = alert.get("category", "unknown")
        severity = alert.get("severity", 3)
        action = alert.get("action", "allowed")
        timestamp = event.get("timestamp", "")
        alert_id = f"suricata_{sig_id}_{src_ip}_{dst_ip}_{int(time.time())}"

        # Suricata severity: 1=high, 2=medium, 3=low
        sev_map = {1: "CRITICAL", 2: "WARNING", 3: "INFO"}
        sev_label = sev_map.get(severity, "INFO")

        if not src_ip or not dst_ip:
            return

        cypher_write("""
            MERGE (r:SuricataRule {signature_id: $sig_id})
            SET r.signature = $signature,
                r.category = $category,
                r.severity = $severity,
                r.action = $action,
                r.updated = timestamp()

            MERGE (a:SuricataAlert {id: $alert_id})
            SET a.signature = $signature,
                a.category = $category,
                a.severity = $sev_label,
                a.severity_num = $severity,
                a.action = $action,
                a.protocol = $proto,
                a.timestamp = $timestamp,
                a.source = 'suricata',
                a.updated = timestamp()

            MERGE (src:Host {ip: $src_ip})
            SET src.last_seen = timestamp()
            MERGE (dst:Host {ip: $dst_ip})
            SET dst.last_seen = timestamp()

            MERGE (a)-[:FROM_HOST]->(src)
            MERGE (a)-[:TO_HOST]->(dst)
            MERGE (a)-[:MATCHES_RULE]->(r)

            MERGE (src)-[r2:ALERTED_BY]->(dst)
            SET r2.last_seen = timestamp(),
                r2.count = coalesce(r2.count, 0) + 1,
                r2.severity = $sev_label
        """, {
            "alert_id": alert_id,
            "sig_id": str(sig_id),
            "signature": signature,
            "category": category,
            "severity": int(severity),
            "sev_label": sev_label,
            "action": action,
            "proto": proto,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        })

        # Feed to Sentinel callback
        if self._on_alert and sev_label in ("CRITICAL", "WARNING"):
            try:
                self._on_alert({
                    "source": "suricata",
                    "alert_type": f"ids_{category}",
                    "severity": sev_label,
                    "description": signature,
                    "source_ip": src_ip,
                    "details": {
                        "signature_id": sig_id,
                        "category": category,
                        "action": action,
                        "protocol": proto,
                    },
                })
            except Exception as e:
                logger.error(f"suricata: error feeding alert to callback: {e}")

    def _store_flow(self, event: dict[str, Any]) -> None:
        """Store a Suricata flow event."""
        if not getattr(self, '_neo4j_ready', False):
            return
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dest_ip", "")
        proto = event.get("proto", "unknown")
        flow = event.get("flow", {})
        pkts_tos = flow.get("pkts_toserver", 0)
        pkts_toc = flow.get("pkts_toclient", 0)
        bytes_tos = flow.get("bytes_toserver", 0)
        bytes_toc = flow.get("bytes_toclient", 0)
        state = flow.get("state", "new")

        if not src_ip or not dst_ip:
            return

        cypher_write("""
            MERGE (src:Host {ip: $src_ip})
            SET src.last_seen = timestamp()
            MERGE (dst:Host {ip: $dst_ip})
            SET dst.last_seen = timestamp()
            MERGE (src)-[r:FLOW]->(dst)
            SET r.protocol = $proto,
                r.state = $state,
                r.packets_toserver = coalesce(r.packets_toserver, 0) + $pkts_tos,
                r.packets_toclient = coalesce(r.packets_toclient, 0) + $pkts_toc,
                r.bytes_toserver = coalesce(r.bytes_toserver, 0) + $bytes_tos,
                r.bytes_toclient = coalesce(r.bytes_toclient, 0) + $bytes_toc,
                r.last_seen = timestamp()
        """, {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "state": state,
            "pkts_tos": int(pkts_tos or 0),
            "pkts_toc": int(pkts_toc or 0),
            "bytes_tos": int(bytes_tos or 0),
            "bytes_toc": int(bytes_toc or 0),
        })

    async def _retry_neo4j_schema(self) -> None:
        """Background task: retry Neo4j schema init every 10s until it works."""
        for attempt in range(30):  # 5 minutes max
            await asyncio.sleep(10)
            if self._init_neo4j_schema():
                self._neo4j_ready = True
                logger.info("suricata: Neo4j schema initialized on retry %d ✅", attempt + 1)
                return
        logger.warning("suricata: gave up on Neo4j after 30 retries — running without graph storage")

    def _store_stats(self, event: dict[str, Any]) -> None:
        """Store Suricata stats event."""
        stats = event.get("stats", {})
        self._last_stats = {
            "capture": stats.get("capture", {}),
            "decode": stats.get("decode", {}),
            "detect": stats.get("detect", {}),
            "drops": stats.get("drop", {}),
        }

    def _process_event(self, event: dict[str, Any]) -> None:
        """Process a single EVE JSON event."""
        event_type = event.get("event_type", "")

        if event_type == "alert":
            self._total_alerts += 1
            self._store_alert(event)
        elif event_type == "flow":
            self._total_flows += 1
            self._store_flow(event)
        elif event_type == "http":
            self._total_http += 1
        elif event_type == "dns":
            self._total_dns += 1
        elif event_type == "tls":
            self._total_tls += 1
        elif event_type == "stats":
            self._total_stats += 1
            self._store_stats(event)
        elif event_type == "drop":
            self._total_drops += 1

    async def _poll_events(self) -> None:
        """Continuous loop: read new events from eve.json."""
        while self._running:
            try:
                if not os.path.exists(EVE_JSON_PATH):
                    logger.warning(f"suricata: eve.json not found at {EVE_JSON_PATH}")
                    await asyncio.sleep(10)
                    continue

                # Open file and seek to last offset
                if self._file_handle is None:
                    self._file_handle = open(EVE_JSON_PATH, "r")
                    self._file_handle.seek(0, 2)  # Seek to end
                    logger.info("suricata: opened eve.json, starting from end")
                    continue

                count = 0
                for line in self._file_handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        self._process_event(event)
                        count += 1
                        if count >= MAX_EVENTS_PER_POLL:
                            break
                    except json.JSONDecodeError:
                        continue

                if count > 0:
                    logger.debug(f"suricata: processed {count} events (alerts: {self._total_alerts}, flows: {self._total_flows})")

            except Exception as e:
                logger.error(f"suricata: poll error: {e}")
            await asyncio.sleep(POLL_INTERVAL)

    async def start(self) -> None:
        """Start the Suricata collector."""
        if self._running:
            return

        logger.info("suricata: starting collector...")
        self._neo4j_ready = self._init_neo4j_schema()
        self._running = True
        asyncio.create_task(self._poll_events())
        if self._neo4j_ready:
            logger.info("suricata: collector started ✅ (polling eve.json every %ds)", POLL_INTERVAL)
        else:
            logger.warning("suricata: collector started ⚠️ (polling eve.json every %ds, Neo4j schema pending)", POLL_INTERVAL)
            # Background retry for Neo4j schema
            asyncio.create_task(self._retry_neo4j_schema())

    async def stop(self) -> None:
        """Stop the Suricata collector."""
        self._running = False
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
        logger.info("suricata: collector stopped")

    def get_stats(self) -> dict[str, Any]:
        """Get collector statistics."""
        import subprocess
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'suricata'],
                capture_output=True, text=True, timeout=5
            )
            suricata_service_active = result.stdout.strip() == 'active'
        except Exception:
            suricata_service_active = False

        return {
            "running": self._running,
            "suricata_service": suricata_service_active,
            "neo4j_connected": getattr(self, '_neo4j_ready', False),
            "total_alerts": self._total_alerts,
            "total_flows": self._total_flows,
            "total_http": self._total_http,
            "total_dns": self._total_dns,
            "total_tls": self._total_tls,
            "total_drops": self._total_drops,
            "total_stats": self._total_stats,
            "eve_json_path": EVE_JSON_PATH,
            "suricata_version": "8.0.6",
            "last_stats": self._last_stats,
        }

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent Suricata alerts from Neo4j."""
        records = cypher_read("""
            MATCH (a:SuricataAlert)
            RETURN a.id AS id, a.signature AS signature, a.category AS category,
                   a.severity AS severity, a.action AS action, a.protocol AS protocol,
                   a.timestamp AS timestamp
            ORDER BY a.timestamp DESC
            LIMIT $limit
        """, {"limit": limit})
        return [dict(r) for r in records]

    def get_top_alerted_hosts(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get hosts with most Suricata alerts."""
        records = cypher_read("""
            MATCH (src:Host)-[r:ALERTED_BY]->(dst:Host)
            RETURN src.ip AS src_ip, dst.ip AS dst_ip, r.count AS alert_count,
                   r.severity AS severity
            ORDER BY alert_count DESC
            LIMIT $limit
        """, {"limit": limit})
        return [dict(r) for r in records]

    def get_rule_summary(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get Suricata rule summary."""
        records = cypher_read("""
            MATCH (r:SuricataRule)
            RETURN r.signature_id AS signature_id, r.signature AS signature,
                   r.category AS category, r.severity AS severity, r.action AS action
            ORDER BY r.severity ASC
            LIMIT $limit
        """, {"limit": limit})
        return [dict(r) for r in records]