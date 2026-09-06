"""Sentinel Attack Detector — correlation engine that maps events to MITRE ATT&CK detections.

Correlates structured log events from LogMonitor into AttackEvent detections,
maintains attacker profiles, and persists everything to Neo4j.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict, deque
from typing import Any

from app.core.database import cypher_read, cypher_write

logger = logging.getLogger(__name__)

# ── Detection thresholds ──────────────────────────────────────────
# SSH — tightened + added low-and-slow detection
SSH_BRUTE_FORCE_THRESHOLD = 5    # failed logins within fast window
SSH_BRUTE_FORCE_WINDOW = 60      # seconds (fast)
SSH_SLOW_THRESHOLD = 15          # failed logins within slow window
SSH_SLOW_WINDOW = 3600           # 1 hour (low-and-slow)
SSH_SPRAY_MIN_USERS = 3          # different users within window

# Web
WEB_SCANNER_THRESHOLD = 20       # 4xx errors within window
WEB_SCANNER_WINDOW = 60           # seconds
DIR_ENUM_MIN_404S = 10           # sequential 404s for sensitive paths
DIR_ENUM_WINDOW = 60             # seconds
WORDLIST_SCAN_THRESHOLD = 40     # 404s on non-sensitive paths (gobuster/ffuf)
WORDLIST_SCAN_WINDOW = 60        # seconds
API_ABUSE_THRESHOLD = 10         # 401/403 on /api/* within window
API_ABUSE_WINDOW = 60            # seconds
REQUEST_RATE_THRESHOLD = 50      # total requests per IP within window
REQUEST_RATE_WINDOW = 10         # seconds (high rate = flooding)

# Credential attacks
CRED_STUFFING_MIN_USERS = 5      # different usernames in login POSTs
CRED_STUFFING_WINDOW = 120       # seconds

# Port scanning
PORT_SCAN_MIN_PORTS = 10         # connections to different closed ports
PORT_SCAN_WINDOW = 60            # seconds

# System events
SUDO_FAIL_THRESHOLD = 3          # sudo failures from same IP
SUDO_FAIL_WINDOW = 300           # 5 minutes

# Severity levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# ── Sensitive paths for directory enumeration ─────────────────────
DIR_ENUM_PATHS = {
    "/admin", "/administrator", "/api", "/api/v1", "/api/v2",
    "/.env", "/.git", "/.git/config", "/.git/HEAD",
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/phpmyadmin", "/pma", "/admin.php",
    "/config.php", "/config.json", "/config.yml",
    "/backup", "/db.sql", "/dump.sql",
    "/.ssh", "/.ssh/id_rsa", "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info", "/xmlrpc.php",
    "/console", "/debug", "/test", "/.well-known",
}

# ── ATT&CK technique lookup ───────────────────────────────────────
TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    # SSH attacks
    "ssh_brute_force": {"id": "T1110.001", "name": "Password Guessing"},
    "ssh_password_spraying": {"id": "T1110.003", "name": "Password Spraying"},
    "ssh_slow_brute": {"id": "T1110.001", "name": "Password Guessing (Low and Slow)"},
    "ssh_successful_after_failures": {"id": "T1078", "name": "Valid Accounts"},
    # Web attacks
    "web_scanner": {"id": "T1595", "name": "Active Scanning"},
    "sqli": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "xss": {"id": "T1059.007", "name": "JavaScript Execution"},
    "cmdi": {"id": "T1059.004", "name": "Unix Shell Injection"},
    "xxe": {"id": "T1190", "name": "XXE External Entity Injection"},
    "ssrf": {"id": "T1190", "name": "Server-Side Request Forgery"},
    "path_traversal": {"id": "T1083", "name": "File and Directory Discovery"},
    "directory_enumeration": {"id": "T1083", "name": "File and Directory Discovery"},
    "wordlist_scan": {"id": "T1595.003", "name": "Wordlist Scanning"},
    "web_shell_access": {"id": "T1505.003", "name": "Web Shell"},
    "method_abuse": {"id": "T1190", "name": "HTTP Method Abuse"},
    "request_flood": {"id": "T1499", "name": "Endpoint Flood DoS"},
    # Credential attacks
    "credential_stuffing": {"id": "T1110.004", "name": "Credential Stuffing"},
    "api_key_abuse": {"id": "T1078.004", "name": "Cloud Accounts (API Key)"},
    # Network recon
    "port_scan": {"id": "T1595.001", "name": "Scanning IP Blocks"},
    "suspicious_ua": {"id": "T1595.002", "name": "Vulnerability Scanning"},
    # System attacks
    "sensitive_file_access": {"id": "T1552.001", "name": "Credentials In Files"},
    "system_anomaly": {"id": "T0000", "name": "System Anomaly"},
    "sudo_escalation": {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
    "user_creation": {"id": "T1098", "name": "Account Manipulation"},
    "cron_tampering": {"id": "T1053.003", "name": "Cron"},
    "log_tampering": {"id": "T1070.002", "name": "Clear Command History"},
    "firewall_tampering": {"id": "T1562.001", "name": "Disable Tools"},
    "process_crash": {"id": "T1190", "name": "Exploit-Induced Crash"},
    # Multi-IP
    "distributed_attack": {"id": "T1110", "name": "Brute Force (Distributed)"},
    # VIGIL integration
    "kernel_rootkit": {"id": "T1014", "name": "Rootkit"},
    "container_escape": {"id": "T1611", "name": "Escape to Host"},
    "c2_communication": {"id": "T1071", "name": "Application Layer Protocol"},
    "cryptojacking": {"id": "T1496", "name": "Resource Hijacking"},
    "dns_exfiltration": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
    "tty_surveillance": {"id": "T1057", "name": "Process Discovery"},
    "privilege_escalation": {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
}


def _get_technique(attack_type: str) -> dict[str, str]:
    """Get MITRE ATT&CK technique info for an attack type."""
    return TECHNIQUE_MAP.get(attack_type, {"id": "T0000", "name": "Unknown"})


# ── AttackEvent ───────────────────────────────────────────────────

class AttackEvent:
    """A single detected attack event."""

    __slots__ = (
        "id", "timestamp", "source_ip", "attack_type", "technique_id",
        "technique_name", "severity", "evidence", "details",
    )

    def __init__(
        self,
        source_ip: str,
        attack_type: str,
        severity: str,
        evidence: list[dict],
        details: dict[str, Any],
    ) -> None:
        tech = _get_technique(attack_type)
        self.id = str(uuid.uuid4())
        self.timestamp = time.time()
        self.source_ip = source_ip
        self.attack_type = attack_type
        self.technique_id = tech["id"]
        self.technique_name = tech["name"]
        self.severity = severity
        self.evidence = evidence
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "attack_type": self.attack_type,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "severity": self.severity,
            "evidence": self.evidence,
            "details": self.details,
        }


# ── AttackerProfile ───────────────────────────────────────────────

class AttackerProfile:
    """Profile of a known attacker IP."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.attack_count = 0
        self.attack_types: set[str] = set()
        self.techniques_used: set[str] = set()
        self.is_blocked = False
        self.detection_history: deque[dict] = deque(maxlen=100)

    def add_detection(self, event: AttackEvent) -> None:
        self.last_seen = time.time()
        self.attack_count += 1
        self.attack_types.add(event.attack_type)
        self.techniques_used.add(event.technique_id)
        self.detection_history.append(event.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "attack_count": self.attack_count,
            "attack_types": sorted(self.attack_types),
            "techniques_used": sorted(self.techniques_used),
            "is_blocked": self.is_blocked,
            "detection_count": len(self.detection_history),
        }


# ── AttackDetector ────────────────────────────────────────────────

class AttackDetector:
    """Correlates log events into attack detections using rolling windows."""

    def __init__(self, on_attack: Any = None) -> None:
        self.on_attack = on_attack  # callback: async def fn(AttackEvent)
        self.attackers: dict[str, AttackerProfile] = {}

        # Rolling windows per IP
        self._ssh_failures: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._ssh_users: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._web_4xx: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._web_404_paths: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._web_all_requests: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._login_attempts: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._port_hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._sudo_failures: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._api_failures: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._wordlist_404s: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))

        # Multi-IP correlation: track targets across IPs
        self._ssh_target_users: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))  # user → [(ts, ip)]
        self._login_target_urls: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))  # url → [(ts, ip)]

    def process_event(self, event: dict) -> AttackEvent | None:
        """Process a raw log event and return an AttackEvent if a detection fired."""
        event_type = event.get("event_type", "")
        ip = event.get("source_ip", "")
        if not ip:
            return None

        ts = event.get("timestamp")
        if isinstance(ts, str):
            ts = time.time()  # approximate
        elif ts is None:
            ts = time.time()

        details = event.get("details", {})
        tags = event.get("tags", [])

        detection: AttackEvent | None = None

        # ── SSH events ──────────────────────────────────────────
        if event_type == "ssh_failed_login" or event_type == "ssh_invalid_user":
            self._ssh_failures[ip].append((ts, details.get("user", "")))
            self._ssh_users[ip].append((ts, details.get("user", "")))
            detection = self._check_ssh_attacks(ip)

        elif event_type == "ssh_accepted":
            # Check if this IP had recent failures (possible successful brute force)
            failures = [t for t, _ in self._ssh_failures[ip] if ts - t < SSH_BRUTE_FORCE_WINDOW]
            if len(failures) >= SSH_BRUTE_FORCE_THRESHOLD:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="ssh_successful_after_failures",
                    severity=CRITICAL,
                    evidence=[{"type": "ssh_accepted", "details": details}],
                    details={
                        "user": details.get("user"),
                        "failed_attempts": len(failures),
                        "message": "SSH login succeeded after multiple failures — possible successful brute force",
                    },
                )

        # ── Web events ──────────────────────────────────────────
        elif event_type == "web_request":
            status = details.get("status", 200)
            url = details.get("url", "")
            method = details.get("method", "GET")
            ua = details.get("user_agent", "")

            # Suspicious user agent
            if "suspicious_ua" in tags:
                tool = details.get("suspected_tool", "unknown")
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="suspicious_ua",
                    severity=MEDIUM,
                    evidence=[event],
                    details={
                        "tool": tool,
                        "user_agent": ua,
                        "url": url,
                    },
                )
                self._record_detection(ip, detection)

            # SQL injection
            if "sqli_attempt" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="sqli",
                    severity=CRITICAL,
                    evidence=[event],
                    details={"url": url, "method": method, "payload": url},
                )
                self._record_detection(ip, detection)

            # XSS
            if "xss_attempt" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="xss",
                    severity=HIGH,
                    evidence=[event],
                    details={"url": url, "method": method},
                )
                self._record_detection(ip, detection)

            # Command injection
            if "cmdi_attempt" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="cmdi",
                    severity=CRITICAL,
                    evidence=[event],
                    details={"url": url, "method": method},
                )
                self._record_detection(ip, detection)

            # XXE
            if "xxe_attempt" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="xxe",
                    severity=CRITICAL,
                    evidence=[event],
                    details={"url": url, "method": method},
                )
                self._record_detection(ip, detection)

            # SSRF
            if "ssrf_attempt" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="ssrf",
                    severity=CRITICAL,
                    evidence=[event],
                    details={"url": url, "method": method},
                )
                self._record_detection(ip, detection)

            # Path traversal
            if "path_traversal" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="path_traversal",
                    severity=HIGH,
                    evidence=[event],
                    details={"url": url, "method": method},
                )
                self._record_detection(ip, detection)

            # Sensitive file access
            if "sensitive_file_access" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="sensitive_file_access",
                    severity=HIGH,
                    evidence=[event],
                    details={"url": url, "sensitive_path": details.get("sensitive_path", "")},
                )
                self._record_detection(ip, detection)

            # Web shell access
            if "web_shell_access" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="web_shell_access",
                    severity=CRITICAL,
                    evidence=[event],
                    details={"url": url, "web_shell": details.get("web_shell", "")},
                )
                self._record_detection(ip, detection)

            # HTTP method abuse
            if "method_abuse" in tags:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="method_abuse",
                    severity=MEDIUM,
                    evidence=[event],
                    details={"url": url, "method": method},
                )
                self._record_detection(ip, detection)

            # API auth failure tracking (for api_key_abuse detection)
            if "api_auth_failure" in tags:
                self._api_failures[ip].append((ts, url))
                recent_api_fails = [t for t, _ in self._api_failures[ip] if ts - t < API_ABUSE_WINDOW]
                if len(recent_api_fails) >= API_ABUSE_THRESHOLD:
                    detection = AttackEvent(
                        source_ip=ip,
                        attack_type="api_key_abuse",
                        severity=HIGH,
                        evidence=[{"timestamp": t, "url": u} for t, u in list(self._api_failures[ip])[-API_ABUSE_THRESHOLD:]],
                        details={
                            "failed_attempts": len(recent_api_fails),
                            "window_seconds": API_ABUSE_WINDOW,
                        },
                    )
                    self._record_detection(ip, detection)

            # Track 4xx for scanner detection
            if status >= 400:
                self._web_4xx[ip].append(ts)
                if status == 404:
                    self._web_404_paths[ip].append((ts, url))
                    # Track non-sensitive 404s for wordlist scanning
                    if not any(s in url.lower() for s in DIR_ENUM_PATHS):
                        self._wordlist_404s[ip].append((ts, url))

                # Check for web scanner pattern
                scanner_det = self._check_web_scanner(ip, ts)
                if scanner_det:
                    self._record_detection(ip, scanner_det)

                # Check for directory enumeration
                dir_enum_det = self._check_directory_enumeration(ip, ts)
                if dir_enum_det:
                    self._record_detection(ip, dir_enum_det)

                # Check for wordlist scanning (gobuster/ffuf — lots of 404s on non-sensitive paths)
                wordlist_det = self._check_wordlist_scan(ip, ts)
                if wordlist_det:
                    self._record_detection(ip, wordlist_det)

            # Track ALL requests for flood detection
            self._web_all_requests[ip].append(ts)
            flood_det = self._check_request_flood(ip, ts)
            if flood_det:
                self._record_detection(ip, flood_det)

            # Track login attempts for credential stuffing
            if "login_attempt" in tags:
                self._login_attempts[ip].append((ts, details.get("url", "")))
                cred_det = self._check_credential_stuffing(ip, ts)
                if cred_det:
                    self._record_detection(ip, cred_det)

            # Multi-IP correlation: track which users are being targeted
            if "login_attempt" in tags or "ssh_failed_login" in event_type:
                target_user = details.get("user", "")
                if target_user:
                    self._ssh_target_users[target_user].append((ts, ip))
                    multi_ip_det = self._check_multi_ip_attack(target_user, ts)
                    if multi_ip_det:
                        self._record_detection(multi_ip_det.source_ip, multi_ip_det)

        # ── System failure events ──────────────────────────────
        elif event_type == "system_failure":
            # These are LOW severity context events
            detection = AttackEvent(
                source_ip=ip,
                attack_type="system_anomaly",
                severity=LOW,
                evidence=[event],
                details={
                    "raw": details.get("raw", "")[:200],
                    "event_type": event_type,
                },
            )
            self._record_detection(ip, detection)

        # ── Sudo escalation attempts (T1548.003) ────────────────
        elif event_type == "sudo_failure":
            self._sudo_failures[ip].append((ts, details.get("user", "")))
            recent_sudo = [t for t, _ in self._sudo_failures[ip] if ts - t < SUDO_FAIL_WINDOW]
            if len(recent_sudo) >= SUDO_FAIL_THRESHOLD:
                detection = AttackEvent(
                    source_ip=ip,
                    attack_type="sudo_escalation",
                    severity=HIGH,
                    evidence=[{"timestamp": t, "type": "sudo_failed"} for t, _ in recent_sudo],
                    details={
                        "user": details.get("user", ""),
                        "failed_attempts": len(recent_sudo),
                        "window_seconds": SUDO_FAIL_WINDOW,
                    },
                )
                self._record_detection(ip, detection)

        # ── User creation (T1098 Account Manipulation) ─────────
        elif event_type == "user_creation":
            detection = AttackEvent(
                source_ip=ip,
                attack_type="user_creation",
                severity=CRITICAL,
                evidence=[event],
                details={
                    "user": details.get("user", ""),
                    "raw": details.get("raw", "")[:200],
                },
            )
            self._record_detection(ip, detection)

        # ── Cron tampering (T1053.003) ────────────────────────
        elif event_type == "cron_tampering":
            detection = AttackEvent(
                source_ip=ip,
                attack_type="cron_tampering",
                severity=HIGH,
                evidence=[event],
                details={"raw": details.get("raw", "")[:200]},
            )
            self._record_detection(ip, detection)

        # ── Log tampering (T1070.002) ──────────────────────────
        elif event_type == "log_tampering":
            detection = AttackEvent(
                source_ip=ip,
                attack_type="log_tampering",
                severity=CRITICAL,
                evidence=[event],
                details={"raw": details.get("raw", "")[:200]},
            )
            self._record_detection(ip, detection)

        # ── Firewall tampering (T1562.001) ────────────────────
        elif event_type == "firewall_tampering":
            detection = AttackEvent(
                source_ip=ip,
                attack_type="firewall_tampering",
                severity=CRITICAL,
                evidence=[event],
                details={"raw": details.get("raw", "")[:200]},
            )
            self._record_detection(ip, detection)

        # ── Process crash (potential exploit) ──────────────────
        elif event_type == "process_crash":
            detection = AttackEvent(
                source_ip=ip,
                attack_type="process_crash",
                severity=MEDIUM,
                evidence=[event],
                details={
                    "process": details.get("process", ""),
                    "raw": details.get("raw", "")[:200],
                },
            )
            self._record_detection(ip, detection)

        # If we got a detection from SSH checks, record it
        if detection and detection.attack_type not in (
            "suspicious_ua", "sqli", "path_traversal",
            "sensitive_file_access", "system_anomaly",
            "ssh_successful_after_failures",
        ):
            self._record_detection(ip, detection)

        return detection

    # ── Detection rules ─────────────────────────────────────────

    def _check_ssh_attacks(self, ip: str) -> AttackEvent | None:
        """Check for SSH brute force, password spraying, or low-and-slow attacks."""
        now = time.time()

        # Recent failures within fast window
        recent_failures = [
            (t, u) for t, u in self._ssh_failures[ip]
            if now - t < SSH_BRUTE_FORCE_WINDOW
        ]
        recent_users = [
            (t, u) for t, u in self._ssh_users[ip]
            if now - t < SSH_BRUTE_FORCE_WINDOW
        ]

        if not recent_failures:
            # Check slow window even if fast window is empty
            slow_failures = [
                (t, u) for t, u in self._ssh_failures[ip]
                if now - t < SSH_SLOW_WINDOW
            ]
            if len(slow_failures) >= SSH_SLOW_THRESHOLD:
                unique_users = {u for _, u in slow_failures if u}
                return AttackEvent(
                    source_ip=ip,
                    attack_type="ssh_slow_brute",
                    severity=HIGH,
                    evidence=[
                        {"timestamp": t, "user": u, "type": "ssh_failed"}
                        for t, u in slow_failures[-20:]
                    ],
                    details={
                        "failed_attempts": len(slow_failures),
                        "target_users": sorted(unique_users),
                        "window_seconds": SSH_SLOW_WINDOW,
                        "pattern": "low_and_slow",
                    },
                )
            return None

        # Brute force: > threshold failures from same IP (fast)
        if len(recent_failures) >= SSH_BRUTE_FORCE_THRESHOLD:
            unique_users = {u for _, u in recent_failures if u}

            # Password spraying: failures for multiple different users
            if len(unique_users) >= SSH_SPRAY_MIN_USERS:
                return AttackEvent(
                    source_ip=ip,
                    attack_type="ssh_password_spraying",
                    severity=HIGH,
                    evidence=[
                        {"timestamp": t, "user": u, "type": "ssh_failed"}
                        for t, u in recent_failures
                    ],
                    details={
                        "failed_attempts": len(recent_failures),
                        "unique_users": sorted(unique_users),
                        "window_seconds": SSH_BRUTE_FORCE_WINDOW,
                    },
                )

            # Regular brute force: many failures, possibly same user
            return AttackEvent(
                source_ip=ip,
                attack_type="ssh_brute_force",
                severity=HIGH,
                evidence=[
                    {"timestamp": t, "user": u, "type": "ssh_failed"}
                    for t, u in recent_failures
                ],
                details={
                    "failed_attempts": len(recent_failures),
                    "target_users": sorted(unique_users),
                    "window_seconds": SSH_BRUTE_FORCE_WINDOW,
                },
            )

        return None

    def _check_web_scanner(self, ip: str, now: float) -> AttackEvent | None:
        """Check for web scanning pattern (many 4xx errors)."""
        recent_4xx = [t for t in self._web_4xx[ip] if now - t < WEB_SCANNER_WINDOW]
        if len(recent_4xx) >= WEB_SCANNER_THRESHOLD:
            return AttackEvent(
                source_ip=ip,
                attack_type="web_scanner",
                severity=HIGH,
                evidence=[
                    {"timestamp": t, "type": "http_4xx"}
                    for t in recent_4xx[-20:]  # last 20 as evidence
                ],
                details={
                    "error_count": len(recent_4xx),
                    "window_seconds": WEB_SCANNER_WINDOW,
                },
            )
        return None

    def _check_directory_enumeration(self, ip: str, now: float) -> AttackEvent | None:
        """Check for directory/file enumeration via 404s on sensitive paths."""
        recent_404s = [
            (t, url) for t, url in self._web_404_paths[ip]
            if now - t < DIR_ENUM_WINDOW
        ]
        if len(recent_404s) < DIR_ENUM_MIN_404S:
            return None

        # Check if they're hitting sensitive paths
        sensitive_hits = [
            (t, url) for t, url in recent_404s
            if any(s in url.lower() for s in DIR_ENUM_PATHS)
        ]
        if len(sensitive_hits) >= 3:
            return AttackEvent(
                source_ip=ip,
                attack_type="directory_enumeration",
                severity=MEDIUM,
                evidence=[
                    {"timestamp": t, "url": url, "type": "404"}
                    for t, url in sensitive_hits[-20:]
                ],
                details={
                    "total_404s": len(recent_404s),
                    "sensitive_hits": len(sensitive_hits),
                    "paths_probed": sorted({url for _, url in sensitive_hits}),
                    "window_seconds": DIR_ENUM_WINDOW,
                },
            )
        return None

    def _check_credential_stuffing(self, ip: str, now: float) -> AttackEvent | None:
        """Check for credential stuffing (many POST to login with different usernames)."""
        recent = [
            (t, url) for t, url in self._login_attempts[ip]
            if now - t < CRED_STUFFING_WINDOW
        ]
        if len(recent) >= CRED_STUFFING_MIN_USERS:
            return AttackEvent(
                source_ip=ip,
                attack_type="credential_stuffing",
                severity=HIGH,
                evidence=[
                    {"timestamp": t, "url": url, "type": "login_post"}
                    for t, url in recent
                ],
                details={
                    "login_attempts": len(recent),
                    "window_seconds": CRED_STUFFING_WINDOW,
                },
            )
        return None

    def _check_wordlist_scan(self, ip: str, now: float) -> AttackEvent | None:
        """Check for wordlist scanning (gobuster/ffuf — lots of 404s on non-sensitive paths)."""
        recent_404s = [
            (t, url) for t, url in self._wordlist_404s[ip]
            if now - t < WORDLIST_SCAN_WINDOW
        ]
        if len(recent_404s) >= WORDLIST_SCAN_THRESHOLD:
            # Check for sequential path patterns (gobuster uses wordlists)
            paths = [url for _, url in recent_404s[-50:]]
            unique_extensions = set()
            for p in paths:
                if "." in p.split("/")[-1]:
                    unique_extensions.add(p.split("/")[-1].split(".")[-1].lower())
            return AttackEvent(
                source_ip=ip,
                attack_type="wordlist_scan",
                severity=MEDIUM,
                evidence=[
                    {"timestamp": t, "url": url, "type": "404_nonsensitive"}
                    for t, url in recent_404s[-20:]
                ],
                details={
                    "total_404s": len(recent_404s),
                    "unique_extensions": sorted(unique_extensions)[:10],
                    "window_seconds": WORDLIST_SCAN_WINDOW,
                    "tool_hint": "gobuster/ffuf/feroxbuster",
                },
            )
        return None

    def _check_request_flood(self, ip: str, now: float) -> AttackEvent | None:
        """Check for request flooding (DoS or aggressive scraping)."""
        recent_requests = [t for t in self._web_all_requests[ip] if now - t < REQUEST_RATE_WINDOW]
        if len(recent_requests) >= REQUEST_RATE_THRESHOLD:
            return AttackEvent(
                source_ip=ip,
                attack_type="request_flood",
                severity=HIGH,
                evidence=[
                    {"timestamp": t, "type": "request"}
                    for t in recent_requests[-20:]
                ],
                details={
                    "request_count": len(recent_requests),
                    "window_seconds": REQUEST_RATE_WINDOW,
                    "rate_per_second": round(len(recent_requests) / REQUEST_RATE_WINDOW, 1),
                },
            )
        return None

    def _check_multi_ip_attack(self, target_user: str, now: float) -> AttackEvent | None:
        """Check for distributed attack — multiple IPs targeting the same user."""
        recent = [
            (t, ip) for t, ip in self._ssh_target_users[target_user]
            if now - t < SSH_BRUTE_FORCE_WINDOW
        ]
        unique_ips = {ip for _, ip in recent}
        if len(unique_ips) >= 3 and len(recent) >= 8:
            # Use the most recent IP as the source
            latest_ip = recent[-1][1]
            return AttackEvent(
                source_ip=latest_ip,
                attack_type="distributed_attack",
                severity=CRITICAL,
                evidence=[
                    {"timestamp": t, "ip": ip, "target_user": target_user}
                    for t, ip in recent
                ],
                details={
                    "target_user": target_user,
                    "attacker_ips": sorted(unique_ips),
                    "total_attempts": len(recent),
                    "window_seconds": SSH_BRUTE_FORCE_WINDOW,
                },
            )
        return None

    # ── Attacker management ─────────────────────────────────────

    def _record_detection(self, ip: str, event: AttackEvent) -> None:
        """Record a detection: update attacker profile and persist to Neo4j.

        Skips whitelisted IPs (localhost, local kernel, private networks) —
        these are not attackers and should never appear in the attacker list.
        """
        # Skip whitelisted / non-attacker IPs
        if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0", "unknown"):
            return

        if ip not in self.attackers:
            self.attackers[ip] = AttackerProfile(ip)
            self._persist_attacker(ip)

        self.attackers[ip].add_detection(event)
        self._persist_attack_event(event)

    def _persist_attacker(self, ip: str) -> None:
        """Create/update Attacker node in Neo4j."""
        profile = self.attackers.get(ip)
        if not profile:
            return
        try:
            cypher_write(
                """
                MERGE (a:Attacker {ip: $ip})
                ON CREATE SET a.first_seen = $first_seen
                SET a.last_seen = $last_seen,
                    a.attack_count = $attack_count,
                    a.attack_types = $attack_types,
                    a.techniques_used = $techniques_used,
                    a.is_blocked = $is_blocked
                """,
                {
                    "ip": profile.ip,
                    "first_seen": profile.first_seen,
                    "last_seen": profile.last_seen,
                    "attack_count": profile.attack_count,
                    "attack_types": sorted(profile.attack_types),
                    "techniques_used": sorted(profile.techniques_used),
                    "is_blocked": profile.is_blocked,
                },
            )
        except Exception as e:
            logger.error("Sentinel: Neo4j attacker persist error: %s", e)

    def _persist_attack_event(self, event: AttackEvent) -> None:
        """Persist an AttackEvent to Neo4j with relationship to Attacker."""
        try:
            cypher_write(
                """
                MATCH (a:Attacker {ip: $ip})
                CREATE (e:AttackEvent {
                    id: $id,
                    timestamp: $timestamp,
                    attack_type: $attack_type,
                    technique_id: $tech_id,
                    technique_name: $tech_name,
                    severity: $severity,
                    evidence: $evidence,
                    details: $details
                })
                CREATE (a)-[:PERPETRATED]->(e)
                """,
                {
                    "ip": event.source_ip,
                    "id": event.id,
                    "timestamp": event.timestamp,
                    "attack_type": event.attack_type,
                    "tech_id": event.technique_id,
                    "tech_name": event.technique_name,
                    "severity": event.severity,
                    "evidence": json.dumps(event.evidence, default=str),
                    "details": json.dumps(event.details, default=str),
                },
            )
            # Also create technique node
            cypher_write(
                """
                MERGE (t:AttackTechnique {id: $tech_id})
                SET t.name = $tech_name
                WITH t
                MATCH (e:AttackEvent {id: $event_id})
                MERGE (e)-[:USES_TECHNIQUE]->(t)
                """,
                {
                    "tech_id": event.technique_id,
                    "tech_name": event.technique_name,
                    "event_id": event.id,
                },
            )
        except Exception as e:
            logger.error("Sentinel: Neo4j event persist error: %s", e)

    def update_attacker_blocked(self, ip: str, blocked: bool) -> None:
        """Update attacker's blocked status in memory and Neo4j."""
        if ip in self.attackers:
            self.attackers[ip].is_blocked = blocked
        try:
            cypher_write(
                "MATCH (a:Attacker {ip: $ip}) SET a.is_blocked = $blocked",
                {"ip": ip, "blocked": blocked},
            )
        except Exception as e:
            logger.error("Sentinel: Neo4j block status update error: %s", e)

    def get_attackers(self) -> list[dict]:
        """Return all known attacker profiles."""
        return [p.to_dict() for p in self.attackers.values()]

    def get_attacker(self, ip: str) -> dict | None:
        """Return a single attacker profile."""
        p = self.attackers.get(ip)
        return p.to_dict() if p else None

    def load_from_neo4j(self) -> None:
        """Load attacker profiles from Neo4j on startup."""
        try:
            results = cypher_read("MATCH (a:Attacker) RETURN a")
            for row in results:
                data = row.get("a", {})
                ip = data.get("ip")
                if not ip:
                    continue
                profile = AttackerProfile(ip)
                profile.first_seen = data.get("first_seen", time.time())
                profile.last_seen = data.get("last_seen", time.time())
                profile.attack_count = data.get("attack_count", 0)
                profile.attack_types = set(data.get("attack_types", []))
                profile.techniques_used = set(data.get("techniques_used", []))
                profile.is_blocked = data.get("is_blocked", False)
                self.attackers[ip] = profile
            logger.info("Sentinel: loaded %d attacker profiles from Neo4j", len(self.attackers))
        except Exception as e:
            logger.error("Sentinel: Neo4j load error: %s", e)