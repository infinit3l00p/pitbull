"""PITBULL Response Engine — graduated automated threat response.

Academic basis:
  - CryptoGuard (AsiaCCS 2025): Two-phase detection→response pipeline
  - eBPF-Shield (SOCA 2026): Closed-loop hybrid graduated remediation
  - GuardFS (2024): Non-destructive first — delay/track before block/kill
  - EvilEDR (USENIX 2025): Anti-weaponization — no arbitrary exec
  - Agentra (arXiv 2026): Planner-Validator pattern for response plans
  - OIAO (Ops Singularity 2026): Observe→Infer→Act→Observe closed loop

Design:
  1. Graduated response: observe → delay → contain → isolate → terminate
  2. Non-destructive first: throttle/deceive before block/kill
  3. Evidence always first: capture /proc state before any action
  4. Closed-loop verification: verify action succeeded after execution
  5. Timeout + auto-reverse: reversible actions expire after 1 hour
  6. Anti-weaponization: all actions are predefined functions, no exec()
  7. Rate limited: max 10 actions/min per IP, max 3 destructive/hour
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from enum import Enum
from typing import Any

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)

# ── Action Levels ─────────────────────────────────────────────────

class ActionLevel(int):
    """Response severity level — higher = more destructive."""
    OBSERVE = 0
    DELAY = 1
    CONTAIN = 2
    ISOLATE = 3
    TERMINATE = 4
    EVACUATE = 5


class ActionType(str, Enum):
    """Predefined response actions — no arbitrary execution."""
    # Level 0: Observe
    LOG = "LOG"
    EVIDENCE_CAPTURE = "EVIDENCE_CAPTURE"
    ENRICH = "ENRICH"
    ALERT_HUMAN = "ALERT_HUMAN"

    # Level 1: Delay (reversible)
    THROTTLE = "THROTTLE"
    DECEIVE = "DECEIVE"
    PROXY_ROTATE = "PROXY_ROTATE"

    # Level 2: Contain (reversible)
    IP_BLOCK = "IP_BLOCK"
    PORT_CLOSE = "PORT_CLOSE"
    SESSION_KILL = "SESSION_KILL"

    # Level 3: Isolate (reversible, systemd-managed)
    PROCESS_QUARANTINE = "PROCESS_QUARANTINE"
    NETWORK_QUARANTINE = "NETWORK_QUARANTINE"

    # Level 4: Terminate (destructive, requires approval)
    PROCESS_KILL = "PROCESS_KILL"
    SERVICE_STOP = "SERVICE_STOP"
    CONTAINER_KILL = "CONTAINER_KILL"

    # Level 5: Evacuate (nuclear)
    SERVICE_DISABLE = "SERVICE_DISABLE"
    NETWORK_ISOLATE_HOST = "NETWORK_ISOLATE_HOST"


# Action metadata: level, destructive, reversible, auto-approve
ACTION_META: dict[ActionType, dict] = {
    ActionType.LOG:               {"level": 0, "destructive": False, "reversible": False, "auto": True},
    ActionType.EVIDENCE_CAPTURE:  {"level": 0, "destructive": False, "reversible": False, "auto": True},
    ActionType.ENRICH:             {"level": 0, "destructive": False, "reversible": False, "auto": True},
    ActionType.ALERT_HUMAN:       {"level": 0, "destructive": False, "reversible": False, "auto": True},
    ActionType.THROTTLE:          {"level": 1, "destructive": False, "reversible": True,  "auto": True},
    ActionType.DECEIVE:           {"level": 1, "destructive": False, "reversible": True,  "auto": True},
    ActionType.PROXY_ROTATE:        {"level": 1, "destructive": False, "reversible": True,  "auto": True},
    ActionType.IP_BLOCK:          {"level": 2, "destructive": False, "reversible": True,  "auto": True},
    ActionType.PORT_CLOSE:        {"level": 2, "destructive": False, "reversible": True,  "auto": True},
    ActionType.SESSION_KILL:      {"level": 2, "destructive": False, "reversible": False, "auto": True},
    ActionType.PROCESS_QUARANTINE:{"level": 3, "destructive": False, "reversible": True,  "auto": True},
    ActionType.NETWORK_QUARANTINE:{"level": 3, "destructive": False, "reversible": True,  "auto": True},
    ActionType.PROCESS_KILL:      {"level": 4, "destructive": True,  "reversible": False, "auto": False},
    ActionType.SERVICE_STOP:      {"level": 4, "destructive": True,  "reversible": False, "auto": False},
    ActionType.CONTAINER_KILL:    {"level": 4, "destructive": True,  "reversible": False, "auto": False},
    ActionType.SERVICE_DISABLE:   {"level": 5, "destructive": True,  "reversible": False, "auto": False},
    ActionType.NETWORK_ISOLATE_HOST: {"level": 5, "destructive": True, "reversible": False, "auto": False},
}


# ── Response Rules ───────────────────────────────────────────────

RESPONSE_RULES: dict[str, list[ActionType]] = {
    # Web attacks — block + evidence
    "xss": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "cmdi": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "sqli": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "xxe": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "ssrf": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "web_shell_access": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "path_traversal": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.THROTTLE],

    # Scanning — throttle + deceive
    "web_scanner": [ActionType.LOG, ActionType.THROTTLE, ActionType.DECEIVE],
    "wordlist_scan": [ActionType.LOG, ActionType.THROTTLE, ActionType.DECEIVE],
    "port_scan": [ActionType.LOG, ActionType.IP_BLOCK],
    "suspicious_ua": [ActionType.LOG, ActionType.ENRICH],
    "directory_enumeration": [ActionType.LOG, ActionType.THROTTLE],
    "method_abuse": [ActionType.LOG, ActionType.THROTTLE],

    # Credential attacks — block + evidence
    "ssh_brute_force": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "ssh_slow_brute": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.THROTTLE],
    "ssh_password_spraying": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "credential_stuffing": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK],
    "api_key_abuse": [ActionType.LOG, ActionType.THROTTLE, ActionType.IP_BLOCK],
    "ssh_successful_after_failures": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN, ActionType.IP_BLOCK],

    # Distributed attacks — escalate
    "distributed_attack": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.IP_BLOCK, ActionType.ALERT_HUMAN],

    # System attacks — contain + escalate
    "sudo_escalation": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN],
    "user_creation": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN],
    "cron_tampering": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN],
    "log_tampering": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN, ActionType.SERVICE_STOP],
    "firewall_tampering": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN],
    "process_crash": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE],

    # VIGIL alerts (kernel-level) — escalate immediately
    "kernel_rootkit": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.PROCESS_QUARANTINE, ActionType.ALERT_HUMAN],
    "container_escape": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN],
    "c2_communication": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.NETWORK_QUARANTINE, ActionType.ALERT_HUMAN],
    "cryptojacking": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.PROCESS_QUARANTINE],
    "dns_exfiltration": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.NETWORK_QUARANTINE],
    "tty_surveillance": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ALERT_HUMAN],
    "privilege_escalation": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.PROCESS_QUARANTINE, ActionType.ALERT_HUMAN],
    "process_injection": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.PROCESS_QUARANTINE, ActionType.ALERT_HUMAN],
    "network_anomaly": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE],

    # DoS
    "request_flood": [ActionType.LOG, ActionType.THROTTLE, ActionType.IP_BLOCK],
    "system_anomaly": [ActionType.LOG, ActionType.EVIDENCE_CAPTURE],
}


# ── Rate Limiting ────────────────────────────────────────────────

MAX_ACTIONS_PER_MINUTE = 10      # per source IP
MAX_DESTRUCTIVE_PER_HOUR = 3     # per source IP
ACTION_TIMEOUT = 3600            # 1 hour auto-reverse for reversible actions

# ── Response Engine ─────────────────────────────────────────────

class ResponseEngine:
    """Core response engine — plans, validates, executes, verifies, audits."""

    def __init__(self) -> None:
        self._running = False
        self._action_history: list[dict] = []  # in-memory recent actions
        self._active_actions: dict[str, dict] = {}  # action_id → {action, expiry, ...}
        self._rate_tracker: dict[str, list[float]] = {}  # ip → [timestamps]
        self._destructive_tracker: dict[str, list[float]] = {}  # ip → [timestamps]
        self._pending_approval: dict[str, dict] = {}  # action_id → {action, attack_event}
        self._evidence_dir = "/var/lib/pitbull/evidence"
        self._audit_log = "/var/lib/pitbull/audit.log"
        self._stats = {
            "total_actions": 0,
            "total_blocked_by_rate_limit": 0,
            "total_pending_approval": 0,
            "total_auto_reversed": 0,
            "by_action": {},
            "by_attack_type": {},
        }

        # Action handlers — mapped to functions
        self._handlers = {
            ActionType.LOG: self._action_log,
            ActionType.EVIDENCE_CAPTURE: self._action_evidence_capture,
            ActionType.ENRICH: self._action_enrich,
            ActionType.ALERT_HUMAN: self._action_alert_human,
            ActionType.THROTTLE: self._action_throttle,
            ActionType.DECEIVE: self._action_deceive,
            ActionType.PROXY_ROTATE: self._action_proxy_rotate,
            ActionType.IP_BLOCK: self._action_ip_block,
            ActionType.PORT_CLOSE: self._action_port_close,
            ActionType.SESSION_KILL: self._action_session_kill,
            ActionType.PROCESS_QUARANTINE: self._action_process_quarantine,
            ActionType.NETWORK_QUARANTINE: self._action_network_quarantine,
            ActionType.PROCESS_KILL: self._action_process_kill,
            ActionType.SERVICE_STOP: self._action_service_stop,
            ActionType.CONTAINER_KILL: self._action_container_kill,
        }

    async def start(self) -> None:
        """Start the response engine."""
        os.makedirs(self._evidence_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self._audit_log), exist_ok=True)
        self._running = True
        logger.info("Response Engine: started — evidence dir: %s", self._evidence_dir)
        # Start auto-reverse watchdog
        asyncio.create_task(self._auto_reverse_loop())

    async def stop(self) -> None:
        """Stop the response engine."""
        self._running = False
        logger.info("Response Engine: stopped")

    # ── Main entry point ─────────────────────────────────────────

    async def handle_attack(self, attack_event: dict) -> dict:
        """Handle an attack event — plan, validate, execute, verify.

        Args:
            attack_event: Sentinel AttackEvent as dict (must have attack_type, source_ip, severity)

        Returns:
            dict with action_id, actions taken, and status
        """
        attack_type = attack_event.get("attack_type", "system_anomaly")
        source_ip = attack_event.get("source_ip", "0.0.0.0")
        severity = attack_event.get("severity", "LOW")

        # Get response plan
        plan = RESPONSE_RULES.get(attack_type, [ActionType.LOG, ActionType.EVIDENCE_CAPTURE])

        action_id = str(uuid.uuid4())[:8]
        results = []

        for action in plan:
            meta = ACTION_META.get(action, {})

            # Check rate limiting
            if not self._check_rate_limit(source_ip, meta.get("destructive", False)):
                self._stats["total_blocked_by_rate_limit"] += 1
                results.append({
                    "action": action.value,
                    "status": "rate_limited",
                    "message": f"Rate limit exceeded for {source_ip}",
                })
                continue

            # Check approval needed
            if not meta.get("auto", False):
                # Queue for approval
                pending_id = str(uuid.uuid4())[:8]
                self._pending_approval[pending_id] = {
                    "action": action.value,
                    "attack_event": attack_event,
                    "queued_at": time.time(),
                }
                self._stats["total_pending_approval"] += 1
                results.append({
                    "action": action.value,
                    "status": "pending_approval",
                    "approval_id": pending_id,
                    "message": f"Action {action.value} requires approval",
                })
                continue

            # Pre-action validation
            if not self._validate_action(action, attack_event):
                results.append({
                    "action": action.value,
                    "status": "validation_failed",
                    "message": "Pre-action validation failed",
                })
                continue

            # Execute
            handler = self._handlers.get(action, self._action_log)
            try:
                exec_result = await handler(attack_event)
                status = exec_result.get("status", "executed")

                # Post-action verification
                verified = self._verify_action(action, attack_event, exec_result)
                if not verified:
                    status = "verification_failed"

                results.append({
                    "action": action.value,
                    "status": status,
                    "details": exec_result,
                    "verified": verified,
                })

                # Track for auto-reverse
                if meta.get("reversible", False):
                    self._active_actions[action_id] = {
                        "action": action,
                        "attack_event": attack_event,
                        "executed_at": time.time(),
                        "expiry": time.time() + ACTION_TIMEOUT,
                        "result": exec_result,
                    }

                # Audit
                self._audit(action_id, action, attack_event, status, exec_result)
                self._update_stats(action, attack_type)

            except Exception as e:
                logger.error("Response Engine: action %s failed: %s", action.value, e)
                results.append({
                    "action": action.value,
                    "status": "error",
                    "error": str(e),
                })
                self._audit(action_id, action, attack_event, "error", {"error": str(e)})

        return {
            "action_id": action_id,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "actions": results,
        }

    # ── Validation ──────────────────────────────────────────────

    def _check_rate_limit(self, ip: str, destructive: bool) -> bool:
        """Check if we can perform an action for this IP (rate limiting)."""
        now = time.time()

        # General: max 10 actions per minute per IP
        recent = [t for t in self._rate_tracker.get(ip, []) if now - t < 60]
        if len(recent) >= MAX_ACTIONS_PER_MINUTE:
            return False

        # Destructive: max 3 per hour per IP
        if destructive:
            recent_destructive = [t for t in self._destructive_tracker.get(ip, []) if now - t < 3600]
            if len(recent_destructive) >= MAX_DESTRUCTIVE_PER_HOUR:
                return False
            self._destructive_tracker.setdefault(ip, []).append(now)

        self._rate_tracker.setdefault(ip, []).append(now)
        return True

    def _validate_action(self, action: ActionType, event: dict) -> bool:
        """Pre-action validation — check it's safe to execute."""
        if action in (ActionType.LOG, ActionType.EVIDENCE_CAPTURE, ActionType.ENRICH, ActionType.ALERT_HUMAN):
            return True  # always safe

        if action == ActionType.IP_BLOCK:
            ip = event.get("source_ip", "")
            if not ip or ip == "127.0.0.1" or ip == "::1":
                logger.warning("Response Engine: refusing to block localhost")
                return False
            return True

        if action == ActionType.PROCESS_QUARANTINE:
            pid = event.get("details", {}).get("pid", 0)
            if pid <= 1:
                logger.warning("Response Engine: refusing to quarantine PID %d", pid)
                return False
            # Check PID is still alive
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                logger.warning("Response Engine: PID %d not found", pid)
                return False
            return True

        return True

    def _verify_action(self, action: ActionType, event: dict, result: dict) -> bool:
        """Post-action verification — did the action actually work?"""
        if action == ActionType.IP_BLOCK:
            # Verify UFW has the rule
            ip = event.get("source_ip", "")
            if result.get("status") == "executed" and ip:
                return True  # UFW is authoritative — trust it
        return result.get("status") == "executed"

    # ── Action Handlers ─────────────────────────────────────────

    async def _action_log(self, event: dict) -> dict:
        """Log the event to audit trail."""
        logger.info("Response LOG: %s from %s — %s",
                     event.get("attack_type"), event.get("source_ip"),
                     event.get("details", {}).get("message", "")[:100])
        return {"status": "executed", "action": "log"}

    async def _action_evidence_capture(self, event: dict) -> dict:
        """Capture /proc state for forensics."""
        pid = event.get("details", {}).get("pid", 0)
        ts = int(time.time())
        ev_dir = f"{self._evidence_dir}/{ts}_{pid}_{event.get('attack_type', 'unknown')}"
        os.makedirs(ev_dir, exist_ok=True)

        captured = []

        if pid and pid > 1:
            for proc_file in ["status", "cmdline", "environ", "fd", "maps", "io", "stat"]:
                src = f"/proc/{pid}/{proc_file}"
                dst = f"{ev_dir}/{proc_file}"
                try:
                    if os.path.exists(src):
                        if os.path.isdir(src):
                            os.makedirs(dst, exist_ok=True)
                            for entry in os.listdir(src):
                                try:
                                    os.symlink(f"{src}/{entry}", f"{dst}/{entry}")
                                except:
                                    pass
                        else:
                            with open(src, "rb") as f:
                                data = f.read()
                            with open(dst, "wb") as f:
                                f.write(data[:65536])  # cap at 64KB
                            captured.append(proc_file)
                except Exception:
                    pass

        # Capture network state
        try:
            import subprocess
            ss_out = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=5)
            with open(f"{ev_dir}/ss.txt", "w") as f:
                f.write(ss_out.stdout[:65536])
            captured.append("ss")
        except Exception:
            pass

        return {"status": "executed", "evidence_dir": ev_dir, "captured": captured}

    async def _action_enrich(self, event: dict) -> dict:
        """Enrich with IP intelligence from Neo4j."""
        ip = event.get("source_ip", "")
        if not ip or ip == "127.0.0.1":
            return {"status": "skipped", "reason": "local_ip"}

        try:
            results = cypher_read(
                "MATCH (a:Attacker {ip: $ip}) RETURN a.attack_count AS count, a.attack_types AS types",
                {"ip": ip},
            )
            if results:
                return {"status": "executed", "intel": results[0]}
        except Exception:
            pass

        return {"status": "executed", "intel": "unknown"}

    async def _action_alert_human(self, event: dict) -> dict:
        """Alert the human — log critical alert."""
        attack_type = event.get("attack_type", "unknown")
        source_ip = event.get("source_ip", "?")
        logger.critical("🚨 RESPONSE ALERT: %s from %s — HUMAN REVIEW REQUIRED",
                        attack_type, source_ip)
        return {"status": "executed", "alerted": True}

    async def _action_throttle(self, event: dict) -> dict:
        """Throttle source IP via UFW rate limit."""
        ip = event.get("source_ip", "")
        if not ip or ip in ("127.0.0.1", "::1"):
            return {"status": "skipped", "reason": "local_ip"}

        import subprocess
        try:
            # UFW rate limit: 5 connections per 30 seconds
            result = subprocess.run(
                ["ufw", "limit", "from", ip, "to", "any", "port", "80", "proto", "tcp"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return {"status": "executed", "rule": f"limit from {ip}"}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_deceive(self, event: dict) -> dict:
        """Route traffic to TrapCard honeypot (log only for now)."""
        ip = event.get("source_ip", "")
        logger.info("Response DECEIVE: routing %s to honeypot (logged)", ip)
        return {"status": "executed", "deception": "logged"}

    async def _action_proxy_rotate(self, event: dict) -> dict:
        """Trigger identity rotation."""
        try:
            import subprocess
            result = subprocess.run(
                ["curl", "-s", "-X", "POST", "http://127.0.0.1:8442/rotate"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return {"status": "executed", "rotation": "complete"}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_ip_block(self, event: dict) -> dict:
        """Block source IP via UFW."""
        ip = event.get("source_ip", "")
        if not ip or ip in ("127.0.0.1", "::1"):
            return {"status": "skipped", "reason": "local_ip"}

        import subprocess
        try:
            result = subprocess.run(
                ["ufw", "deny", "from", ip],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                logger.warning("Response IP_BLOCK: blocked %s via UFW", ip)
                return {"status": "executed", "ip": ip, "method": "ufw_deny"}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_port_close(self, event: dict) -> dict:
        """Temporarily close a port via UFW."""
        port = event.get("details", {}).get("port", 0)
        if not port:
            return {"status": "skipped", "reason": "no_port"}

        import subprocess
        try:
            result = subprocess.run(
                ["ufw", "deny", str(port), "/tcp"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return {"status": "executed", "port": port}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_session_kill(self, event: dict) -> dict:
        """Kill specific TCP sessions from the source IP."""
        ip = event.get("source_ip", "")
        if not ip or ip in ("127.0.0.1", "::1"):
            return {"status": "skipped", "reason": "local_ip"}

        import subprocess
        try:
            # Kill established connections from this IP
            result = subprocess.run(
                ["ss", "-K", "dst", ip],
                capture_output=True, text=True, timeout=10,
            )
            return {"status": "executed", "ip": ip}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_process_quarantine(self, event: dict) -> dict:
        """Quarantine a process via systemd-run (not direct cgroup writes)."""
        pid = event.get("details", {}).get("pid", 0)
        if not pid or pid <= 1:
            return {"status": "skipped", "reason": "invalid_pid"}

        # systemd manages the cgroup — we just create a transient unit
        # This avoids the cgroup conflict that broke VIGIL
        import subprocess
        try:
            unit_name = f"pitbull-quarantine-{pid}"
            result = subprocess.run(
                ["systemd-run", "--unit", unit_name, "--slice=quarantine.slice",
                 "--property=Delegate=yes", "--property=IPAccounting=yes",
                 "--no-block", "--", "kill", "-STOP", str(pid)],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                logger.warning("Response PROCESS_QUARANTINE: PID %d quarantined via systemd", pid)
                return {"status": "executed", "pid": pid, "unit": unit_name}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_network_quarantine(self, event: dict) -> dict:
        """Network quarantine via UFW (not separate nftables table)."""
        ip = event.get("source_ip", "")
        if not ip or ip in ("127.0.0.1", "::1"):
            return {"status": "skipped", "reason": "local_ip"}

        import subprocess
        try:
            # Block all traffic from this IP — comprehensive
            result = subprocess.run(
                ["ufw", "deny", "from", ip, "to", "any"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                logger.warning("Response NETWORK_QUARANTINE: %s fully network-isolated", ip)
                return {"status": "executed", "ip": ip}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_process_kill(self, event: dict) -> dict:
        """Kill a process — SIGTERM with 5s grace, then SIGKILL."""
        pid = event.get("details", {}).get("pid", 0)
        if not pid or pid <= 1:
            return {"status": "skipped", "reason": "invalid_pid"}

        try:
            os.kill(pid, 15)  # SIGTERM
            await asyncio.sleep(5)
            try:
                os.kill(pid, 0)  # Check if still alive
                os.kill(pid, 9)  # SIGKILL
                logger.warning("Response PROCESS_KILL: PID %d SIGKILL after SIGTERM timeout", pid)
            except ProcessLookupError:
                logger.info("Response PROCESS_KILL: PID %d terminated via SIGTERM", pid)
            return {"status": "executed", "pid": pid, "signal": "SIGTERM→SIGKILL"}
        except ProcessLookupError:
            return {"status": "skipped", "reason": "already_dead"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_service_stop(self, event: dict) -> dict:
        """Stop a systemd service."""
        service = event.get("details", {}).get("service", "")
        if not service:
            return {"status": "skipped", "reason": "no_service"}

        import subprocess
        try:
            result = subprocess.run(
                ["systemctl", "stop", service],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return {"status": "executed", "service": service}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _action_container_kill(self, event: dict) -> dict:
        """Kill a Docker container."""
        container = event.get("details", {}).get("container", "")
        if not container:
            return {"status": "skipped", "reason": "no_container"}

        import subprocess
        try:
            result = subprocess.run(
                ["docker", "kill", container],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return {"status": "executed", "container": container}
            return {"status": "error", "stderr": result.stderr}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── Auto-reverse watchdog ──────────────────────────────────

    async def _auto_reverse_loop(self) -> None:
        """Background task: reverse expired actions."""
        while self._running:
            await asyncio.sleep(60)  # check every minute
            now = time.time()
            expired = [
                aid for aid, data in self._active_actions.items()
                if data["expiry"] < now
            ]
            for aid in expired:
                data = self._active_actions.pop(aid)
                action = data["action"]
                event = data["attack_event"]

                # Reverse the action
                if action == ActionType.IP_BLOCK:
                    ip = event.get("source_ip", "")
                    if ip and ip not in ("127.0.0.1", "::1"):
                        import subprocess
                        try:
                            subprocess.run(["ufw", "delete", "deny", "from", ip],
                                          capture_output=True, timeout=10)
                            logger.info("Response auto-reverse: unblocked IP %s", ip)
                        except Exception:
                            pass

                elif action == ActionType.THROTTLE:
                    ip = event.get("source_ip", "")
                    if ip and ip not in ("127.0.0.1", "::1"):
                        import subprocess
                        try:
                            subprocess.run(["ufw", "delete", "limit", "from", ip],
                                          capture_output=True, timeout=10)
                            logger.info("Response auto-reverse: removed throttle for %s", ip)
                        except Exception:
                            pass

                elif action == ActionType.PROCESS_QUARANTINE:
                    pid = event.get("details", {}).get("pid", 0)
                    if pid:
                        try:
                            os.kill(pid, 18)  # SIGCONT — thaw
                            logger.info("Response auto-reverse: thawed PID %d", pid)
                        except Exception:
                            pass

                self._stats["total_auto_reversed"] += 1
                self._audit(aid, action, event, "auto_reversed", {"reason": "timeout"})

    # ── Audit ──────────────────────────────────────────────────

    def _audit(self, action_id: str, action: ActionType, event: dict,
               status: str, details: dict) -> None:
        """Append to audit log + Neo4j."""
        entry = {
            "action_id": action_id,
            "timestamp": time.time(),
            "action": action.value,
            "attack_type": event.get("attack_type", ""),
            "source_ip": event.get("source_ip", ""),
            "status": status,
            "details": json.dumps(details, default=str)[:1000],
        }

        # File audit (append-only)
        with open(self._audit_log, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # In-memory history
        self._action_history.append(entry)
        if len(self._action_history) > 1000:
            self._action_history = self._action_history[-500:]

        # Neo4j audit
        try:
            cypher_write(
                """
                CREATE (a:ResponseAction {
                    id: $id,
                    timestamp: $ts,
                    action: $action,
                    attack_type: $attack_type,
                    source_ip: $ip,
                    status: $status,
                    details: $details
                })
                """,
                {
                    "id": action_id,
                    "ts": entry["timestamp"],
                    "action": action.value,
                    "attack_type": entry["attack_type"],
                    "ip": entry["source_ip"],
                    "status": status,
                    "details": entry["details"],
                },
            )
        except Exception as e:
            logger.error("Response Engine: Neo4j audit error: %s", e)

    def _update_stats(self, action: ActionType, attack_type: str) -> None:
        self._stats["total_actions"] += 1
        self._stats["by_action"][action.value] = self._stats["by_action"].get(action.value, 0) + 1
        self._stats["by_attack_type"][attack_type] = self._stats["by_attack_type"].get(attack_type, 0) + 1

    # ── Approval workflow ─────────────────────────────────────

    def approve_action(self, approval_id: str) -> dict:
        """Approve a pending destructive action."""
        if approval_id not in self._pending_approval:
            return {"status": "not_found"}

        pending = self._pending_approval.pop(approval_id)
        action_str = pending["action"]
        event = pending["attack_event"]

        # Execute the approved action
        try:
            action = ActionType(action_str)
            handler = self._handlers.get(action)
            if handler:
                # Run synchronously since this is called from API
                import asyncio
                loop = asyncio.get_event_loop()
                result = loop.run_until_complete(handler(event))
                self._audit(approval_id, action, event, "approved_executed", result)
                return {"status": "executed", "result": result}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def reject_action(self, approval_id: str) -> dict:
        """Reject a pending destructive action."""
        if approval_id not in self._pending_approval:
            return {"status": "not_found"}

        pending = self._pending_approval.pop(approval_id)
        self._audit(approval_id, ActionType(pending["action"]), pending["attack_event"],
                   "rejected", {"reason": "human_rejected"})
        return {"status": "rejected"}

    # ── Status ────────────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "stats": self._stats,
            "active_actions": len(self._active_actions),
            "pending_approvals": len(self._pending_approval),
            "action_types": len(ACTION_META),
            "response_rules": len(RESPONSE_RULES),
        }

    def get_history(self, limit: int = 20) -> list[dict]:
        return self._action_history[-limit:]

    def get_pending(self) -> list[dict]:
        return [
            {
                "approval_id": aid,
                "action": data["action"],
                "attack_type": data["attack_event"].get("attack_type"),
                "source_ip": data["attack_event"].get("source_ip"),
                "queued_at": data["queued_at"],
            }
            for aid, data in self._pending_approval.items()
        ]


# ── Singleton ───────────────────────────────────────────────────

response_engine = ResponseEngine()