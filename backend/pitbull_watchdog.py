#!/usr/bin/env python3
"""PITBULL Neo4j Watchdog — prevents data loss and ensures uptime.

Monitors Neo4j health every 30 seconds:
1. Checks Neo4j container is running (restarts if stopped)
2. Checks Bolt connection works (restarts container if not)
3. Checks node count > 0 (alerts if drops to 0)
4. Checks PITBULL backend can reach Neo4j (restarts backend if not)
5. Logs all events to /var/log/pitbull-watchdog.log
6. Sends SSE events to PITBULL if backend is running

Runs as a systemd service: pitbull-watchdog.service
"""

import subprocess
import time
import logging
import os
import signal
import sys
from datetime import datetime
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────
NEO4J_CONTAINER = os.environ.get("PITBULL_NEO4J_CONTAINER", "pitbull-neo4j")
NEO4J_BOLT_URL = os.environ.get("PITBULL_NEO4J_BOLT_URL", "bolt://localhost:7687")
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("PITBULL_NEO4J_PASSWORD", "")
BACKEND_PORT = 8001
BACKEND_START_CMD = "cd " + os.path.dirname(os.path.abspath(__file__)) + " && python3 -m uvicorn app.main:app --host 127.0.0.1 --port " + str(BACKEND_PORT)
CHECK_INTERVAL = 30  # seconds
MAX_RESTART_ATTEMPTS = 3
RESTART_COOLDOWN = 60  # seconds between restart attempts
RECOVERY_MAX_ATTEMPTS = 2  # max Neo4j restarts for data recovery before giving up
LOG_FILE = "/var/log/pitbull-watchdog.log"
STATE_FILE = "/var/run/pitbull-watchdog-state.json"

# ── Logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("pitbull-watchdog")

# ── State ───────────────────────────────────────────────────────────
_last_node_count = None
_last_restart_time = 0
_restart_attempts = 0
_recovery_attempts = 0
_running = True


def handle_signal(signum, frame):
    global _running
    _running = False
    log.info("Received signal %s — shutting down", signum)


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def run_cmd(cmd, timeout=15):
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip() + result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)


def check_neo4j_container():
    """Check if Neo4j Docker container is running."""
    ok, output = run_cmd(f"docker inspect --format='{{{{.State.Running}}}}' {NEO4J_CONTAINER} 2>/dev/null")
    if ok and "true" in output:
        return True
    return False


def restart_neo4j_container():
    """Restart the Neo4j Docker container."""
    log.warning("Restarting Neo4j container...")
    ok, output = run_cmd(f"docker restart {NEO4J_CONTAINER}", timeout=60)
    if ok:
        log.info("Neo4j container restarted — waiting for Bolt to be ready...")
        # Wait for Bolt to be available
        for i in range(30):
            time.sleep(5)
            if check_neo4j_bolt():
                log.info("Neo4j Bolt connection established after %d seconds", (i + 1) * 5)
                return True
        log.error("Neo4j Bolt did not become available after 150 seconds")
        return False
    else:
        log.error("Failed to restart Neo4j container: %s", output)
        return False


def check_neo4j_bolt():
    """Check if Neo4j Bolt connection works and return node count."""
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            NEO4J_BOLT_URL,
            auth=(NEO4J_USER, NEO4J_PASSWORD),
        )
        with driver.session() as session:
            result = session.run("MATCH (n) RETURN count(n) AS total")
            count = result.single()["total"]
        driver.close()
        return True, count
    except Exception as e:
        return False, 0


def check_backend():
    """Check if PITBULL backend is responding."""
    ok, output = run_cmd(f"curl -sf http://127.0.0.1:{BACKEND_PORT}/health -o /dev/null", timeout=10)
    return ok


def restart_backend():
    """Restart the PITBULL backend."""
    log.warning("Restarting PITBULL backend...")
    # Kill existing process
    run_cmd(f"fuser -k {BACKEND_PORT}/tcp 2>/dev/null")
    time.sleep(2)
    # Start new process
    subprocess.Popen(
        BACKEND_START_CMD,
        shell=True,
        stdout=open("/tmp/pitbull-backend.log", "w"),
        stderr=subprocess.STDOUT,
    )
    log.info("Backend restart initiated — waiting for health check...")
    for i in range(12):
        time.sleep(5)
        if check_backend():
            log.info("Backend healthy after %d seconds", (i + 1) * 5)
            return True
    log.error("Backend did not become healthy after 60 seconds")
    return False


def check_docker_volume():
    """Check if Neo4j data volume exists and has data."""
    ok, output = run_cmd(f"docker volume inspect backend_neo4j_data 2>/dev/null")
    if not ok:
        log.error("Neo4j data volume 'backend_neo4j_data' not found!")
        return False
    
    # Check if volume has data files
    ok, output = run_cmd(f"docker exec {NEO4J_CONTAINER} ls -la /data/databases/ 2>/dev/null", timeout=10)
    if ok and "neo4j" in output:
        return True
    log.warning("Neo4j databases directory appears empty: %s", output[:200])
    return False


def save_state(state):
    """Save watchdog state to file."""
    try:
        import json
        Path(os.path.dirname(STATE_FILE)).mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def main_loop():
    global _last_node_count, _last_restart_time, _restart_attempts
    
    log.info("🐲 PITBULL Neo4j Watchdog started — checking every %ds", CHECK_INTERVAL)
    
    while _running:
        now = time.time()
        actions_taken = []
        
        # 1. Check Docker container is running
        if not check_neo4j_container():
            actions_taken.append("Neo4j container not running")
            # Check cooldown
            if now - _last_restart_time < RESTART_COOLDOWN:
                log.warning("Restart cooldown active — waiting...")
            elif _restart_attempts < MAX_RESTART_ATTEMPTS:
                _restart_attempts += 1
                _last_restart_time = now
                if restart_neo4j_container():
                    _restart_attempts = 0
                    actions_taken.append("Neo4j container restarted successfully")
                else:
                    actions_taken.append("Neo4j container restart FAILED")
            else:
                log.critical("Max restart attempts reached — giving up on Neo4j container")
        else:
            _restart_attempts = 0
        
        # 2. Check Bolt connection and node count
        bolt_ok, node_count = check_neo4j_bolt()
        if not bolt_ok:
            actions_taken.append("Neo4j Bolt connection failed")
            if now - _last_restart_time < RESTART_COOLDOWN:
                log.warning("Restart cooldown active — waiting...")
            elif _restart_attempts < MAX_RESTART_ATTEMPTS:
                _restart_attempts += 1
                _last_restart_time = now
                restart_neo4j_container()
                actions_taken.append("Attempted Neo4j restart due to Bolt failure")
        else:
            _restart_attempts = 0
            _recovery_attempts = 0  # reset recovery counter when Neo4j is healthy
            
            # 3. Check for data loss (node count dropped to 0)
            if node_count == 0:
                log.critical("🚨 DATA LOSS DETECTED — Neo4j has 0 nodes!")
                actions_taken.append("DATA LOSS: 0 nodes detected")
                
                # Check if volume has data
                if check_docker_volume():
                    log.warning("Volume has data files — may need manual recovery")
                    actions_taken.append("Volume has data — manual recovery needed")
                else:
                    log.error("Volume appears empty — data may be lost")
                    actions_taken.append("Volume empty — data lost")
                
                # Attempt recovery: restart Neo4j to force transaction log replay
                # Only try this a limited number of times — if data is truly gone,
                # restarting won't help and just causes downtime
                if _recovery_attempts < RECOVERY_MAX_ATTEMPTS and now - _last_restart_time > RESTART_COOLDOWN:
                    _recovery_attempts += 1
                    _last_restart_time = now
                    log.warning("Attempting Neo4j container restart for recovery (attempt %d/%d)...",
                               _recovery_attempts, RECOVERY_MAX_ATTEMPTS)
                    if restart_neo4j_container():
                        actions_taken.append("Neo4j restarted for recovery")
                        # Re-check node count after restart
                        bolt_ok2, node_count2 = check_neo4j_bolt()
                        if bolt_ok2 and node_count2 > 0:
                            log.info("✅ RECOVERY SUCCESSFUL — Neo4j has %d nodes after restart", node_count2)
                            actions_taken.append(f"Recovery successful: {node_count2} nodes restored")
                            _last_node_count = node_count2
                            _recovery_attempts = 0  # reset on success
                        else:
                            log.error("❌ Recovery failed — Neo4j still has 0 nodes after restart")
                            actions_taken.append("Recovery failed: 0 nodes after restart")
                    else:
                        actions_taken.append("Neo4j restart failed")
                elif _recovery_attempts >= RECOVERY_MAX_ATTEMPTS:
                    actions_taken.append("Recovery attempts exhausted — data needs manual rebuild")
                    log.error("Recovery attempts exhausted (%d/%d) — data needs manual rebuild via exploration missions",
                             _recovery_attempts, RECOVERY_MAX_ATTEMPTS)
            elif _last_node_count is not None and node_count < _last_node_count * 0.5:
                log.warning("⚠️ Significant node count drop: %d → %d (−%d)", 
                           _last_node_count, node_count, _last_node_count - node_count)
                actions_taken.append(f"Node count dropped from {_last_node_count} to {node_count}")
            
            _last_node_count = node_count
        
        # 4. Check backend is responding
        if not check_backend():
            actions_taken.append("Backend not responding")
            if now - _last_restart_time < RESTART_COOLDOWN:
                log.warning("Backend restart cooldown active — waiting...")
            else:
                _last_restart_time = now
                restart_backend()
                actions_taken.append("Backend restart attempted")
        
        # 5. Log status
        if actions_taken:
            log.warning("Actions taken: %s", "; ".join(actions_taken))
        else:
            log.info("All systems healthy — Neo4j: %d nodes, Bolt: %s, Backend: OK", 
                     node_count if bolt_ok else "?", "✓" if bolt_ok else "✗")
        
        # 6. Save state
        save_state({
            "timestamp": datetime.now().isoformat(),
            "neo4j_container": check_neo4j_container(),
            "neo4j_bolt": bolt_ok,
            "node_count": node_count if bolt_ok else None,
            "backend": check_backend(),
            "restart_attempts": _restart_attempts,
            "last_restart": datetime.fromtimestamp(_last_restart_time).isoformat() if _last_restart_time else None,
            "actions": actions_taken,
        })
        
        # Sleep between checks
        for _ in range(CHECK_INTERVAL):
            if not _running:
                break
            time.sleep(1)
    
    log.info("PITBULL Neo4j Watchdog stopped")


if __name__ == "__main__":
    # Ensure log directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    main_loop()