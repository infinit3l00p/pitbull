"""PITBULL — FastAPI application entry point."""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict, deque
import time

from app.api import explore, graph, personality, sse, intelligence, deep, darknet, evolution, polish, threat, exploit, antiforensics
from app.api import sentinel as sentinel_api
from app.api import sentinel_investigate
from app.api import response as response_api
from app.api import labyrinth as labyrinth_api
from app.api import trapcard as trapcard_api
from app.api import ntopng as ntopng_api
from app.api import suricata as suricata_api
from app.api import brainmaze as brainmaze_api
from app.api import cerberus as cerberus_api
from app.api import conference_watcher as conference_api
from app.api import defense as defense_api
from app.config import settings
from app.core.database import close_driver, init_schema, test_connection
from app.core.sentinel.sentinel_engine import sentinel_engine

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── API Key ────────────────────────────────────────────────────────
_api_key = os.environ.get("PITBULL_API_KEY") or settings.api_key
if not os.environ.get("PITBULL_API_KEY"):
    logger.info(f"🔐 PITBULL API key: {_api_key}")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)):
    if not api_key or not secrets.compare_digest(api_key.encode(), _api_key.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key. Provide X-API-Key header.")


# ── Lifespan ───────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🔱 PITBULL starting up...")

    # Init Neo4j
    if test_connection():
        init_schema()
        logger.info("✅ Neo4j connected and schema initialized")
    else:
        logger.warning("⚠️ Neo4j not available — running without memory graph")

    # Start Sentinel attack detection engine
    try:
        await sentinel_engine.start()
        logger.info("🛡️ Sentinel engine started — monitoring for attacks")
    except Exception as e:
        logger.warning(f"⚠️ Sentinel engine failed to start: {e}")

    # Init TrapCard Neo4j schema + capture directory
    try:
        from app.trapcard import init_neo4j_schema as trapcard_schema
        trapcard_schema()
        os.makedirs("/opt/pitbull/captured_tools", exist_ok=True)
        logger.info("🪤 TrapCard schema initialized — capture dir ready")
    except Exception as e:
        logger.warning(f"⚠️ TrapCard schema init failed: {e}")

    # Init Cerberus Neo4j schema
    try:
        from app.cerberus import init_neo4j_schema as cerberus_schema
        cerberus_schema()
        logger.info("🔬 Cerberus schema initialized")
    except Exception as e:
        logger.warning(f"⚠️ Cerberus schema init failed: {e}")

    # Init Conference Watcher Neo4j schema
    try:
        from app.conference_watcher import init_neo4j_schema as conf_schema
        conf_schema()
        logger.info("👀 Conference Watcher schema initialized")
    except Exception as e:
        logger.warning(f"⚠️ Conference Watcher schema init failed: {e}")

    # Init BrainMaze Neo4j schema
    try:
        from app.brainmaze import init_neo4j_schema as brainmaze_schema
        brainmaze_schema()
        logger.info("🧠 BrainMaze schema initialized")
    except Exception as e:
        logger.warning(f"⚠️ BrainMaze schema init failed: {e}")

    # Start ntopng collector — feeds live traffic data into graph + Sentinel
    try:
        from app.api.ntopng import init_collector

        ntopng_collector = init_collector()
        # Wire ntopng alerts into Sentinel's attack detection
        ntopng_collector._on_alert = sentinel_engine._on_vigil_alert
        await ntopng_collector.start()
        logger.info("📡 ntopng collector started — live traffic ingestion active")
    except Exception as e:
        logger.warning(f"⚠️ ntopng collector failed to start: {e}")

    # Start Suricata collector — feeds IDS/IPS alerts into graph + Sentinel
    try:
        from app.api.suricata import init_collector as init_suricata

        suricata_collector = init_suricata()
        suricata_collector._on_alert = sentinel_engine._on_vigil_alert
        await suricata_collector.start()
        logger.info("🛡️ Suricata collector started — IDS/IPS alert ingestion active")
    except Exception as e:
        logger.warning(f"⚠️ Suricata collector failed to start: {e}")

    # Wire Sentinel → Labyrinth bridge: feed attack detections into recon detector
    try:
        from app.core.sentinel.sentinel_engine import set_labyrinth_callback
        from app.labyrinth.recon_detector import get_recon_detector, ReconType, ThreatLevel
        from app.labyrinth.controller import get_labyrinth_controller

        recon = get_recon_detector()
        controller = get_labyrinth_controller()
        recon.set_labyrinth_engine(controller)

        _attack_type_map = {
            "ssh_brute_force": "auth",
            "password_spraying": "auth",
            "credential_stuffing": "auth",
            "web_scanner": "http",
            "suspicious_ua": "http",
            "sql_injection": "http",
            "path_traversal": "http",
            "directory_enumeration": "http",
            "sensitive_file_access": "http",
            "port_scan": "connection",
            "ssh_success_after_failures": "auth",
        }

        def _sentinel_to_labyrinth(event):
            """Bridge Sentinel attack events into Labyrinth recon detector."""
            ip = event.source_ip
            attack_type = event.attack_type
            handler = _attack_type_map.get(attack_type, "connection")

            if handler == "auth":
                recon.process_auth(ip, username="unknown", success=False, service="ssh")
            elif handler == "http":
                # Extract path from evidence if available
                path = "/"
                ua = ""
                ev = event.evidence if isinstance(event.evidence, list) else [event.evidence]
                for e in ev:
                    if isinstance(e, dict):
                        details = e.get("details", {})
                        raw = details.get("raw", "") if isinstance(details, dict) else ""
                        if "GET " in raw or "POST " in raw:
                            parts = raw.split('"')
                            if len(parts) >= 2:
                                req = parts[1].split(" ")
                                if len(req) >= 2:
                                    path = req[1]
                        ua_match = [p for p in raw.split('"') if "Mozilla" in p or "Nmap" in p or "sqlmap" in p or "nikto" in p]
                        if ua_match:
                            ua = ua_match[-1]
                recon.process_http(ip, method="GET", path=path, user_agent=ua)
            elif handler == "connection":
                recon.process_connection(ip, dest_port=0, protocol="tcp")

            logger.info("Sentinel→Labyrinth: fed %s attack from %s to recon detector", attack_type, ip)

        set_labyrinth_callback(_sentinel_to_labyrinth)
        logger.info("🔗 Sentinel→Labyrinth bridge connected")
    except Exception as e:
        logger.warning(f"⚠️ Sentinel→Labyrinth bridge failed: {e}")

    yield

    # Stop Sentinel
    try:
        await sentinel_engine.stop()
        logger.info("🛡️ Sentinel engine stopped")
    except Exception:
        pass

    close_driver()
    logger.info("🔱 PITBULL shut down")


# ── App ────────────────────────────────────────────────────────────
app = FastAPI(
    title="PITBULL",
    description="Autonomous Benevolent Yielding & Forensic Intelligence System",
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rate Limiting ──────────────────────────────────────────────────
class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter — 60 req/min per client IP.
    SSE/health/docs endpoints are exempt."""
    def __init__(self, app, max_requests=60, window_s=60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_s = window_s
        self.hits: dict[str, deque] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Skip rate limiting for SSE, health, docs, frontend
        # FIX (audit 17:45): the exemption list had /sentinel/stream and
        # /brainmaze/stream — paths that DON'T EXIST. The real feeds are
        # /sentinel/feed, /labyrinth/feed, /brainmaze/feed, /cerberus/feed,
        # /trapcard/feed — ALL rate-limited → EventSource 429 → "OFFLINE"
        # badges. Labyrinth died first (heaviest polling). Rule now: any
        # /api/v1/*/feed is an SSE stream → exempt (legacy paths kept).
        if path.startswith(("/api/v1/sse", "/api/v1/sentinel/stream", "/api/v1/brainmaze/stream",
                            "/api/v1/sentinel/feed", "/api/v1/labyrinth/feed", "/api/v1/brainmaze/feed",
                            "/api/v1/cerberus/feed", "/api/v1/trapcard/feed",
                            "/health", "/docs", "/openapi", "/redoc", "/assets")) \
           or path.endswith("/feed"):
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        now = time.time()
        q = self.hits[client]
        # Evict old entries
        while q and q[0] < now - self.window_s:
            q.popleft()
        # FIX (heartbeat 21:05): backend binds 127.0.0.1 only — every client
        # IS the local dashboard. Its designed polling ALONE exceeded the old
        # 60/min cap (defense panel: 5 endpoints × every 5s = 60/min), so
        # labyrinth/sentinel STATUS polls got zero budget → 429s, and the
        # frontend's no-backoff retries kept the bucket saturated. Loopback
        # is the trusted frontend → 10x headroom (600/min still caps runaway
        # retry storms). If the backend is ever bound externally, non-loopback
        # clients keep the strict 60/min default.
        limit = self.max_requests * 10 if client in ("127.0.0.1", "::1") else self.max_requests
        if len(q) >= limit:
            return JSONResponse(
                status_code=429,
                content={"detail": f"Rate limit exceeded: {limit} requests per {self.window_s}s"},
            )
        q.append(now)
        return await call_next(request)

app.add_middleware(RateLimitMiddleware, max_requests=60, window_s=60)

# ── Health & Root (registered BEFORE catch-all) ────────────────────
@app.get("/health")
async def health():
    neo4j_ok = test_connection()
    return {
        "status": "healthy" if neo4j_ok else "degraded",
        "app": "PITBULL",
        "version": settings.app_version,
        "neo4j": {"connected": neo4j_ok},
    }


@app.get("/api")
async def api_root():
    return {
        "name": "PITBULL",
        "version": settings.app_version,
        "description": "Autonomous Benevolent Yielding & Forensic Intelligence System",
        "docs": "/docs",
        "health": "/health",
    }


# ── API Routes ─────────────────────────────────────────────────────
app.include_router(explore.router, prefix="/api/v1/explore", dependencies=[Depends(verify_api_key)])
app.include_router(graph.router, prefix="/api/v1/graph", dependencies=[Depends(verify_api_key)])
app.include_router(personality.router, prefix="/api/v1/personality", dependencies=[Depends(verify_api_key)])
app.include_router(sse.router, prefix="/api/v1/sse", tags=["sse"])  # SSE routes are public for EventSource compatibility
app.include_router(intelligence.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(deep.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(darknet.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(evolution.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(polish.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(threat.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(exploit.router, prefix="/api/v1/exploit", dependencies=[Depends(verify_api_key)])
app.include_router(antiforensics.router, prefix="/api/v1/antiforensics", dependencies=[Depends(verify_api_key)])

# ── Defense Modules (Sentinel + Labyrinth) ────────────────────────
app.include_router(sentinel_api.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(sentinel_investigate.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(response_api.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(labyrinth_api.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
# SSE feed endpoints are public (EventSource doesn't support custom headers)
app.include_router(sentinel_api.public_router, prefix="/api/v1", tags=["sentinel"])
app.include_router(labyrinth_api.public_router, prefix="/api/v1", tags=["labyrinth"])

# ── Phase 8 Modules (TrapCard + BrainMaze + Cerberus + Conference Watcher) ──
app.include_router(trapcard_api.router, prefix="/api/v1/trapcard", dependencies=[Depends(verify_api_key)])
app.include_router(trapcard_api.public_router, prefix="/api/v1/trapcard", tags=["trapcard"])
app.include_router(ntopng_api.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(suricata_api.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(brainmaze_api.router, prefix="/api/v1/brainmaze", dependencies=[Depends(verify_api_key)])
app.include_router(brainmaze_api.public_router, prefix="/api/v1/brainmaze", tags=["brainmaze"])
app.include_router(defense_api.router, prefix="/api/v1", dependencies=[Depends(verify_api_key)])
app.include_router(defense_api.public_router, prefix="/api/v1", tags=["defense"])
app.include_router(cerberus_api.router, prefix="/api/v1/cerberus", dependencies=[Depends(verify_api_key)])
app.include_router(cerberus_api.public_router, prefix="/api/v1/cerberus", tags=["cerberus"])
app.include_router(conference_api.router, prefix="/api/v1/conferences", dependencies=[Depends(verify_api_key)])

# ── Frontend (serves built React app) ──────────────────────────────
_frontend_dist = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "frontend", "dist"
)
if os.path.isdir(_frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(_frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Catch-all for SPA routing — serves index.html for non-API paths."""
        # Don't intercept API, docs, or health routes
        if full_path.startswith(("api/", "docs", "openapi", "redoc", "health")):
            raise HTTPException(status_code=404)
        # Serve specific static files if they exist
        file_path = os.path.join(_frontend_dist, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        # Otherwise return index.html for SPA routing
        index = os.path.join(_frontend_dist, "index.html")
        if os.path.isfile(index):
            return FileResponse(index)
        raise HTTPException(status_code=404)
    logger.info(f"Frontend served from {_frontend_dist}")
else:
    logger.info("No frontend dist found — API-only mode")

    @app.get("/")
    async def root():
        return {
            "name": "PITBULL",
            "version": settings.app_version,
            "description": "Autonomous Benevolent Yielding & Forensic Intelligence System",
            "docs": "/docs",
            "health": "/health",
        }