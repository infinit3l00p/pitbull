"""ntopng collector — real-time network traffic intelligence.

Pulls live flow data, alerts, and host statistics from ntopng's REST API
and feeds them into PITBULL's Neo4j graph + Sentinel attack detection.

ntopng REST API v2: https://ntop.org/guides/ntopng/api/rest/api_v2.html

Data collected:
- Active flows (source/dest IP, protocol, bytes, packets, duration)
- Alerts (intrusion detection, anomalous traffic, rogue services)
- Host statistics (traffic volume, connection count, first/last seen)

Graph model:
  (:Host {ip}) -[:CONNECTED_TO {protocol, bytes, packets}]-> (:Host {ip})
  (:Flow {id}) -[:FROM]-> (:Host)
  (:Flow {id}) -[:TO]-> (:Host)
  (:Alert {id, type, severity}) -[:CONCERNS]-> (:Host)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────
NTOPNG_URL = "http://127.0.0.1:3000"
NTOPNG_USER = "admin"
NTOPNG_PASS = "DaVDiMW8.S~76@B"
POLL_INTERVAL = 30  # seconds between flow polls
ALERT_POLL_INTERVAL = 15  # seconds between alert polls (faster — alerts are critical)
SESSION_REFRESH_INTERVAL = 300  # refresh auth cookie every 5 min
MAX_FLOWS_PER_POLL = 500
MAX_ALERTS_PER_POLL = 100


class NtopngCollector:
    """Polls ntopng REST API for live traffic data and feeds PITBULL."""

    def __init__(self, on_alert_callback=None):
        self.base_url = NTOPNG_URL
        self.username = NTOPNG_USER
        self.password: str = NTOPNG_PASS
        self.client = httpx.AsyncClient(timeout=15.0)
        self._cookie: str | None = None
        self._running = False
        self._last_flow_ts = 0
        self._last_alert_ts = 0
        self._total_flows = 0
        self._total_alerts = 0
        self._total_hosts = 0
        self._on_alert = on_alert_callback

        # Override from env
        import os
        env_pass = os.environ.get("NTOPNG_PASSWORD")
        if env_pass:
            self.password = env_pass
        env_url = os.environ.get("NTOPNG_URL")
        if env_url:
            self.base_url = env_url

    # ── Auth ───────────────────────────────────────────────────────

    async def _login(self) -> bool:
        """Authenticate with ntopng and store session cookie.

        ntopng uses form-based auth via /authorize.html (not REST /rest/login).
        Returns a session_3000_0 cookie on success.
        With --disable-login 1, no auth is needed — we just verify the server is up.
        """
        try:
            # First try without auth — if --disable-login is set, ntopng accepts all requests
            resp = await self.client.get(
                f"{self.base_url}/lua/flows_stats.lua?ifid=0",
                follow_redirects=True,
            )
            # If we can access pages without being redirected to login, auth is disabled
            if resp.status_code == 200 and "login.lua" not in str(resp.url) and "wrong-credentials" not in str(resp.url):
                # Auth is disabled — no cookie needed, but set a dummy one
                self._cookie = "disable-login"
                logger.info("ntopng: auth disabled (no login required) ✅")
                return True
            
            # Auth is enabled — try form-based login
            resp = await self.client.post(
                f"{self.base_url}/authorize.html",
                data={
                    "_username": self.username,
                    "password": self.password,
                    "user": self.username,
                    "referer": "",
                },
                follow_redirects=True,
            )
            # Check if we got a valid session cookie
            for cookie in self.client.cookies.jar:
                if "session" in cookie.name and cookie.value:
                    self._cookie = f"{cookie.name}={cookie.value}"
                    logger.info(f"ntopng: authenticated ✅ (cookie: {cookie.name})")
                    return True
            # If we got redirected to login page with wrong-credentials, auth failed
            if "wrong-credentials" in str(resp.url) or "login" in str(resp.url):
                logger.warning("ntopng: login failed — wrong credentials")
                return False
            logger.warning(f"ntopng: login failed (HTTP {resp.status_code})")
            return False
        except Exception as e:
            logger.error(f"ntopng: login error: {e}")
            return False

    def _headers(self) -> dict:
        """Build request headers with auth cookie."""
        headers = {"Content-Type": "application/json"}
        if self._cookie:
            headers["Cookie"] = self._cookie
        return headers

    # ── Flow Collection ────────────────────────────────────────────

    async def get_active_flows(self, ifid: int = 0) -> list[dict[str, Any]]:
        """Get active flows from ntopng via the lua API.

        ntopng Community doesn't have a REST API — we use the lua endpoint
        and parse the HTML-wrapped JSON response.
        """
        try:
            resp = await self.client.get(
                f"{self.base_url}/lua/get_flows_data.lua",
                params={"ifid": ifid, "perPage": MAX_FLOWS_PER_POLL, "currentPage": 1},
                headers=self._headers(),
                follow_redirects=True,
            )
            if resp.status_code != 200 or not resp.text.strip():
                return []
            import json as json_mod
            data = json_mod.loads(resp.text)
            flows = []
            for f in data.get("data", []):
                # Parse HTML-wrapped fields
                import re
                cli_match = re.search(r"host=([0-9a-f:.]+)", f.get("column_client", ""))
                srv_match = re.search(r"host=([0-9a-f:.]+)", f.get("column_server", ""))
                ndpi = re.sub(r"<[^>]+>", "", f.get("column_ndpi", "")).strip()
                proto = f.get("column_proto_l4", "").split()[0] if f.get("column_proto_l4") else ""
                flows.append({
                    "id": f.get("key"),
                    "cli_ip": cli_match.group(1) if cli_match else "",
                    "srv_ip": srv_match.group(1) if srv_match else "",
                    "proto": proto,
                    "ndpi": ndpi,
                    "bytes": f.get("column_bytes", 0),
                    "duration": f.get("column_duration", ""),
                    "first_seen": f.get("column_first_seen", ""),
                    "last_seen": f.get("column_last_seen", ""),
                })
            return flows
        except Exception as e:
            logger.error(f"ntopng: error fetching flows: {e}")
            return []

    async def get_alerts(self, ifid: int = 0) -> list[dict[str, Any]]:
        """Get recent alerts from ntopng SQLite database directly.

        ntopng Community stores alerts in /var/lib/ntopng/<ifid>/alerts/alert_store_v11.db
        We read this SQLite DB directly — no API needed.
        """
        try:
            import subprocess, json as json_mod, sqlite3, os, tempfile

            # Copy the alert DB from the container to a temp file
            db_path = f"/var/lib/ntopng/{ifid}/alerts/alert_store_v11.db"
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                tmp_path = tmp.name

            result = subprocess.run(
                ["docker", "cp", f"ntopng:{db_path}", tmp_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.warning(f"ntopng: could not copy alert DB: {result.stderr}")
                return []

            # Read alerts from SQLite
            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT rowid, alert_id, tstamp, severity, score, cli_ip, srv_ip, "
                "cli_port, srv_port, proto, l7_proto, cli2srv_bytes, srv2cli_bytes, "
                "is_cli_attacker, is_srv_attacker, json, info "
                "FROM flow_alerts ORDER BY tstamp DESC LIMIT ?",
                (MAX_ALERTS_PER_POLL,)
            )
            alerts = []
            for row in cursor:
                alert = dict(row)
                # Parse the JSON details field
                try:
                    details = json_mod.loads(alert.get("json", "{}"))
                    alert["details"] = details
                    # Extract alert type from details
                    alerts_map = details.get("alerts", {})
                    if alerts_map:
                        first_alert = list(alerts_map.values())[0]
                        alert["alert_type"] = first_alert.get("alert_generation", {}).get("script_key", "unknown")
                    else:
                        alert["alert_type"] = f"alert_{alert.get('alert_id', 'unknown')}"
                except Exception:
                    alert["details"] = {}
                    alert["alert_type"] = f"alert_{alert.get('alert_id', 'unknown')}"
                alerts.append(alert)
            conn.close()
            os.unlink(tmp_path)
            return alerts

        except Exception as e:
            logger.error(f"ntopng: error fetching alerts: {e}")
            return []

    async def get_hosts(self, ifid: int = 0) -> list[dict[str, Any]]:
        """Get active hosts from ntopng via the lua API."""
        try:
            resp = await self.client.get(
                f"{self.base_url}/lua/get_host_data.lua",
                params={"ifid": ifid, "perPage": 500, "currentPage": 1},
                headers=self._headers(),
                follow_redirects=True,
            )
            if resp.status_code != 200 or not resp.text.strip():
                return []
            import json as json_mod
            data = json_mod.loads(resp.text)
            hosts = data.get("data", [])
            return hosts
        except Exception as e:
            logger.error(f"ntopng: error fetching hosts: {e}")
            return []

    # ── Graph Storage ──────────────────────────────────────────────

    def _store_flow(self, flow: dict[str, Any]) -> None:
        """Store a single flow as a graph relationship in Neo4j."""
        src_ip = flow.get("cli_ip", flow.get("src_ip", ""))
        dst_ip = flow.get("srv_ip", flow.get("dst_ip", ""))
        proto = flow.get("proto", flow.get("l4_proto", "unknown"))
        bytes_sent = flow.get("bytes", flow.get("tot_bytes", 0))
        port = flow.get("port", flow.get("srv_port", flow.get("dst_port", 0)))
        ndpi = flow.get("ndpi", "")
        flow_id = flow.get("id", flow.get("key", f"{src_ip}_{dst_ip}_{proto}_{int(time.time())}"))
        first_seen = flow.get("first_seen", "")
        last_seen = flow.get("last_seen", "")

        if not src_ip or not dst_ip:
            return

        # Safely convert to int
        try:
            bytes_int = int(bytes_sent) if bytes_sent else 0
        except (ValueError, TypeError):
            bytes_int = 0
        try:
            port_int = int(str(port).split(":")[0]) if port else 0
        except (ValueError, TypeError):
            port_int = 0

        # Create source host, dest host, flow node, and relationships
        cypher_write("""
            MERGE (src:Host {ip: $src_ip})
            ON CREATE SET src.first_seen = timestamp(), src.total_flows = 0
            SET src.last_seen = timestamp(), src.total_flows = src.total_flows + 1

            MERGE (dst:Host {ip: $dst_ip})
            ON CREATE SET dst.first_seen = timestamp(), dst.total_flows = 0
            SET dst.last_seen = timestamp(), dst.total_flows = dst.total_flows + 1

            MERGE (f:Flow {id: $flow_id})
            SET f.protocol = $proto,
                f.bytes = $bytes_int,
                f.port = $port_int,
                f.ndpi = $ndpi,
                f.first_seen = $first_seen,
                f.last_seen = $last_seen,
                f.updated = timestamp()

            MERGE (src)-[:SENT {flow_id: $flow_id}]->(f)
            MERGE (f)-[:TO]->(dst)

            MERGE (src)-[r:CONNECTED_TO]->(dst)
            SET r.protocol = $proto,
                r.last_seen = timestamp(),
                r.total_bytes = coalesce(r.total_bytes, 0) + $bytes_int
        """, {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "flow_id": str(flow_id),
            "proto": str(proto),
            "bytes_int": bytes_int,
            "port_int": port_int,
            "ndpi": str(ndpi),
            "first_seen": str(first_seen),
            "last_seen": str(last_seen),
        })

    def _store_alert(self, alert: dict[str, Any]) -> None:
        """Store an ntopng alert in Neo4j and notify Sentinel callback."""
        alert_id = alert.get("rowid", alert.get("id", f"ntopng_{int(time.time()*1000)}"))
        alert_type = alert.get("alert_type", "unknown")
        severity_map = {0: "INFO", 1: "NOTICE", 2: "WARNING", 3: "ERROR", 4: "CRITICAL", 5: "EMERGENCY"}
        severity = severity_map.get(alert.get("severity", 2), "WARNING")
        description = alert.get("info", alert.get("alert_type", ""))
        src_ip = str(alert.get("cli_ip", ""))
        dst_ip = str(alert.get("srv_ip", ""))
        timestamp = alert.get("tstamp", int(time.time()))
        score = alert.get("score", 0)
        proto_num = alert.get("proto", 0)
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
        protocol = proto_map.get(proto_num, str(proto_num)) if proto_num else ""
        cli_port = alert.get("cli_port", 0)
        srv_port = alert.get("srv_port", 0)
        bytes_sent = alert.get("cli2srv_bytes", 0)
        bytes_recv = alert.get("srv2cli_bytes", 0)
        info = alert.get("info", "")
        
        # Extract flow risk info from JSON details
        details = alert.get("details", {})
        flow_risks = details.get("flow_risk_info", {})
        if flow_risks:
            description = "; ".join(flow_risks.values())
        
        # Extract alert score from details
        alerts_map = details.get("alerts", {})
        if alerts_map and not score:
            first_alert = list(alerts_map.values())[0]
            score = first_alert.get("score", 0)

        # Store in Neo4j
        cypher_write("""
            MERGE (a:NetworkAlert {id: $alert_id})
            SET a.type = $alert_type,
                a.severity = $severity,
                a.description = $description,
                a.source = 'ntopng',
                a.timestamp = $timestamp,
                a.score = $score,
                a.source_ip = $src_ip,
                a.dest_ip = $dst_ip,
                a.protocol = $protocol,
                a.cli_port = $cli_port,
                a.srv_port = $srv_port,
                a.bytes_sent = $bytes_sent,
                a.bytes_recv = $bytes_recv,
                a.info = $info,
                a.updated = timestamp()
            WITH a
            FOREACH (_ IN CASE WHEN $src_ip <> '' THEN [1] ELSE [] END |
                MERGE (h:Host {ip: $src_ip})
                MERGE (a)-[:CONCERNS]->(h)
            )
            WITH a
            FOREACH (_ IN CASE WHEN $dst_ip <> '' THEN [1] ELSE [] END |
                MERGE (h:Host {ip: $dst_ip})
                MERGE (a)-[:CONCERNS]->(h)
            )
        """, {
            "alert_id": str(alert_id),
            "alert_type": str(alert_type),
            "severity": str(severity),
            "description": str(description),
            "src_ip": str(src_ip or ""),
            "dst_ip": str(dst_ip or ""),
            "timestamp": int(timestamp or time.time()),
            "score": int(score or 0),
            "protocol": str(protocol),
            "cli_port": int(cli_port or 0),
            "srv_port": int(srv_port or 0),
            "bytes_sent": int(bytes_sent or 0),
            "bytes_recv": int(bytes_recv or 0),
            "info": str(info or ""),
        })

        # Feed to Sentinel callback if registered
        if self._on_alert and severity in ("ERROR", "CRITICAL", "EMERGENCY", "WARNING"):
            try:
                self._on_alert({
                    "source": "ntopng",
                    "alert_type": alert_type,
                    "severity": severity,
                    "description": description,
                    "source_ip": src_ip or "unknown",
                    "details": alert,
                })
            except Exception as e:
                logger.error(f"ntopng: error feeding alert to callback: {e}")

    def _store_host(self, host: dict[str, Any]) -> None:
        """Store/update a host in Neo4j."""
        ip = host.get("ip", host.get("host", ""))
        if not ip:
            return

        name = host.get("name", host.get("hostname", ""))
        traffic = host.get("traffic", {})
        bytes_sent = traffic.get("sent", {}).get("bytes", 0) if isinstance(traffic, dict) else 0
        bytes_recv = traffic.get("recv", {}).get("bytes", 0) if isinstance(traffic, dict) else 0
        country = host.get("country", host.get("geo", {}).get("country", ""))

        cypher_write("""
            MERGE (h:Host {ip: $ip})
            SET h.name = $name,
                h.country = $country,
                h.bytes_sent = $bytes_sent,
                h.bytes_recv = $bytes_recv,
                h.last_seen = timestamp()
            WITH h
            MERGE (n:NtopngHost {ip: $ip})
            SET n.last_updated = timestamp(),
                n.bytes_sent = $bytes_sent,
                n.bytes_recv = $bytes_recv
        """, {
            "ip": str(ip),
            "name": str(name or ""),
            "country": str(country or ""),
            "bytes_sent": int(bytes_sent or 0),
            "bytes_recv": int(bytes_recv or 0),
        })

    # ── Polling Loops ──────────────────────────────────────────────

    async def _poll_flows(self) -> None:
        """Continuous loop: poll flows, store in graph."""
        while self._running:
            try:
                flows = await self.get_active_flows()
                for flow in flows:
                    self._store_flow(flow)
                self._total_flows += len(flows)
                logger.debug(f"ntopng: polled {len(flows)} flows (total: {self._total_flows})")
            except Exception as e:
                logger.error(f"ntopng: flow poll error: {e}")
            await asyncio.sleep(POLL_INTERVAL)

    async def _poll_alerts(self) -> None:
        """Continuous loop: poll alerts, store + feed to Sentinel."""
        while self._running:
            try:
                alerts = await self.get_alerts()
                new_alerts = []
                for alert in alerts:
                    alert_ts = alert.get("tstamp", alert.get("timestamp", 0))
                    if alert_ts and int(alert_ts) > self._last_alert_ts:
                        new_alerts.append(alert)
                        self._store_alert(alert)
                if new_alerts:
                    self._total_alerts += len(new_alerts)
                    self._last_alert_ts = max(
                        (a.get("tstamp", a.get("timestamp", 0)) for a in new_alerts),
                        default=self._last_alert_ts,
                    )
                    logger.info(f"ntopng: {len(new_alerts)} new alerts (total: {self._total_alerts})")
            except Exception as e:
                logger.error(f"ntopng: alert poll error: {e}")
            await asyncio.sleep(ALERT_POLL_INTERVAL)

    async def _poll_hosts(self) -> None:
        """Continuous loop: poll hosts, update graph."""
        while self._running:
            try:
                hosts = await self.get_hosts()
                for host in hosts:
                    self._store_host(host)
                self._total_hosts = len(hosts)
                logger.debug(f"ntopng: polled {len(hosts)} hosts")
            except Exception as e:
                logger.error(f"ntopng: host poll error: {e}")
            await asyncio.sleep(POLL_INTERVAL)

    async def _refresh_auth(self) -> None:
        """Periodically refresh the auth session."""
        while self._running:
            await asyncio.sleep(SESSION_REFRESH_INTERVAL)
            await self._login()

    # ── Lifecycle ──────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the ntopng collector."""
        if self._running:
            logger.warning("ntopng: collector already running")
            return

        logger.info("ntopng: starting collector...")
        if not await self._login():
            logger.error("ntopng: cannot start collector — login failed")
            logger.error(f"ntopng: check credentials at {self.base_url} (user={self.username})")
            return

        self._running = True

        # Init Neo4j schema for ntopng nodes
        self._init_neo4j_schema()

        # Start polling loops
        asyncio.create_task(self._poll_flows())
        asyncio.create_task(self._poll_alerts())
        # asyncio.create_task(self._poll_hosts())  # Disabled — endpoint 404s in Community
        asyncio.create_task(self._refresh_auth())

        logger.info("ntopng: collector started ✅ (flows=%ds, alerts=%ds, hosts=%ds)",
                     POLL_INTERVAL, ALERT_POLL_INTERVAL, POLL_INTERVAL)

    async def stop(self) -> None:
        """Stop the ntopng collector."""
        self._running = False
        logger.info("ntopng: collector stopped")

    def _init_neo4j_schema(self) -> None:
        """Initialize Neo4j constraints for ntopng data."""
        cypher_write("CREATE CONSTRAINT flow_id IF NOT EXISTS FOR (f:Flow) REQUIRE f.id IS UNIQUE")
        cypher_write("CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE")
        cypher_write("CREATE CONSTRAINT network_alert_id IF NOT EXISTS FOR (a:NetworkAlert) REQUIRE a.id IS UNIQUE")
        cypher_write("CREATE CONSTRAINT ntopng_host IF NOT EXISTS FOR (n:NtopngHost) REQUIRE n.ip IS UNIQUE")
        logger.info("ntopng: Neo4j schema initialized")

    # ── Stats ──────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Get collector statistics."""
        return {
            "running": self._running,
            "total_flows": self._total_flows,
            "total_alerts": self._total_alerts,
            "total_hosts": self._total_hosts,
            "base_url": self.base_url,
        }

    # ── Query ──────────────────────────────────────────────────────

    def get_top_talkers(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get top hosts by traffic volume from Neo4j."""
        records = cypher_read("""
            MATCH (h:Host)-[r:CONNECTED_TO]->()
            RETURN h.ip AS ip, h.name AS name, h.country AS country,
                   sum(r.total_bytes) AS total_bytes, count(r) AS connections
            ORDER BY total_bytes DESC
            LIMIT $limit
        """, {"limit": limit})
        return [dict(r) for r in records]

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent network alerts from Neo4j with full detail."""
        records = cypher_read("""
            MATCH (a:NetworkAlert)
            OPTIONAL MATCH (a)-[:CONCERNS]->(h:Host)
            RETURN a.id AS id, a.type AS type, a.severity AS severity,
                   a.description AS description, a.timestamp AS timestamp,
                   a.source_ip AS source_ip, a.dest_ip AS dest_ip,
                   a.protocol AS protocol, a.score AS score,
                   a.bytes_sent AS bytes_sent, a.bytes_recv AS bytes_recv,
                   a.cli_port AS cli_port, a.srv_port AS srv_port,
                   a.info AS info, collect(h.ip) AS concerned_hosts
            ORDER BY a.timestamp DESC
            LIMIT $limit
        """, {"limit": limit})
        return [dict(r) for r in records]

    def get_suspicious_hosts(self) -> list[dict[str, Any]]:
        """Get hosts with alerts against them."""
        records = cypher_read("""
            MATCH (a:NetworkAlert)-[:CONCERNS]->(h:Host)
            WHERE a.severity IN ['ERROR', 'CRITICAL', 'EMERGENCY']
            RETURN h.ip AS ip, h.name AS name, count(a) AS alert_count,
                   collect(a.type)[0..5] AS alert_types
            ORDER BY alert_count DESC
        """)
        return [dict(r) for r in records]