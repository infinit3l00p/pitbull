"""Reconnaissance Detector — identifies attacker activity and triggers MirrorGraph.

This module monitors for signs of attacker reconnaissance:
- Port scanning (Nmap, masscan)
- DNS enumeration (subdomain brute-forcing, zone transfer attempts)
- Service fingerprinting (banner grabbing, HTTP probing)
- Credential discovery (LDAP queries, SMB enumeration)
- Web crawling (automated directory enumeration, .git exposure checks)

When reconnaissance is detected, the system:
1. Activates the MirrorGraph (if not already active)
2. Begins serving fabricated data to the reconnaissance source
3. Starts the epistemic erosion engine
4. Logs the attacker's confidence level (estimated)

Academic basis:
- Polad et al. 2019: "We try to sabotage the reconnaissance and scanning steps"
- Dykstra & Shortridge 2022: sludge should be deployed "before, during, and after"
- Kumar et al.: hypothesis-testing framework for sludging
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════
#  RECONNAISSANCE EVENT TYPES
# ═══════════════════════════════════════════════════════════════════════

class ReconType(str, Enum):
    """Types of reconnaissance activity the system detects."""
    PORT_SCAN = "port_scan"              # Sequential port probing
    DNS_ENUM = "dns_enum"                # Subdomain brute-forcing
    SERVICE_FINGERPRINT = "service_fingerprint"  # Banner grabbing
    WEB_CRAWL = "web_crawl"               # Directory enumeration
    CRED_DISCOVERY = "cred_discovery"    # Credential searching
    NETWORK_DISCOVERY = "network_discovery"  # Internal network mapping
    VULN_SCAN = "vuln_scan"              # Active vulnerability scanning
    OS_FINGERPRINT = "os_fingerprint"    # OS detection attempts


class ThreatLevel(str, Enum):
    """Escalating threat levels based on reconnaissance intensity."""
    NORMAL = "normal"        # No recon detected
    SUSPICIOUS = "suspicious"  # Low-level recon, could be admin activity
    RECON = "recon"          # Active reconnaissance confirmed
    INTRUSION = "intrusion"  # Attacker is inside, pivoting
    CRITICAL = "critical"    # Active exploitation attempt


# ═══════════════════════════════════════════════════════════════════════
#  RECON EVENT DATA
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ReconEvent:
    """A single reconnaissance event detected by the system."""
    event_id: str
    recon_type: ReconType
    source_ip: str
    timestamp: datetime
    details: dict[str, Any]
    severity: str = "medium"  # low, medium, high, critical
    confidence: float = 0.5   # 0.0-1.0 how confident we are this is malicious


@dataclass
class AttackerProfile:
    """Profile of a detected attacker, built up over time."""
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    recon_events: list[ReconEvent] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.NORMAL
    estimated_skill: str = "unknown"  # script_kiddie, intermediate, advanced, apt
    estimated_confidence: float = 1.0  # attacker's estimated confidence (1.0 = full confidence)
    hypothesis_count: int = 0   # how many times they've tested "is this real?"
    dead_ends_hit: int = 0      # how many MirrorGraph paths led nowhere
    tools_detected: list[str] = field(default_factory=list)  # nmap, gobuster, etc.

    def escalate(self, new_level: ThreatLevel) -> None:
        """Escalate threat level (never de-escalate during active engagement)."""
        levels = list(ThreatLevel)
        current_idx = levels.index(self.threat_level)
        new_idx = levels.index(new_level)
        if new_idx > current_idx:
            self.threat_level = new_level
            logger.warning(
                "EPHEMERAL LABYRINTH: Threat escalated for %s → %s",
                self.source_ip, new_level.value,
            )

    def erode_confidence(self, amount: float = 0.05) -> None:
        """Reduce the attacker's estimated confidence by a small amount."""
        self.estimated_confidence = max(0.0, self.estimated_confidence - amount)
        self.dead_ends_hit += 1
        logger.info(
            "EPHEMERAL LABYRINTH: Attacker %s confidence eroded to %.0f%% "
            "(dead ends: %d, hypotheses tested: %d)",
            self.source_ip, self.estimated_confidence * 100,
            self.dead_ends_hit, self.hypothesis_count,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "threat_level": self.threat_level.value,
            "estimated_skill": self.estimated_skill,
            "estimated_confidence": round(self.estimated_confidence, 3),
            "hypothesis_count": self.hypothesis_count,
            "dead_ends_hit": self.dead_ends_hit,
            "tools_detected": self.tools_detected,
            "recon_event_count": len(self.recon_events),
        }


# ═══════════════════════════════════════════════════════════════════════
#  DETECTION RULES
# ═══════════════════════════════════════════════════════════════════════

# Port scan detection thresholds
PORT_SCAN_THRESHOLD = 5  # connections to 5+ different ports within 60s = port scan
PORT_SCAN_WINDOW = 60    # seconds

# DNS enumeration thresholds
DNS_ENUM_THRESHOLD = 20   # 20+ DNS queries for different subdomains within 60s
DNS_ENUM_WINDOW = 60

# Web crawl thresholds
WEB_CRAWL_THRESHOLD = 15  # 15+ HTTP requests to different paths within 60s
WEB_CRAWL_WINDOW = 60

# Tool signatures (from User-Agent or banner patterns)
TOOL_SIGNATURES = {
    "nmap": ["nmap", "Nmap", "Nmap Scripting Engine"],
    "masscan": ["masscan"],
    "gobuster": ["gobuster"],
    "dirb": ["dirb"],
    "dirbuster": ["dirbuster"],
    "wfuzz": ["wfuzz"],
    "nikto": ["nikto"],
    "sqlmap": ["sqlmap"],
    "hydra": ["hydra"],
    "john": ["John the Ripper"],
    "legion": ["legion"],
    "recon-ng": ["recon-ng"],
    "theharvester": ["theHarvester"],
    "amass": ["amass"],
    "subfinder": ["subfinder"],
    "httpx": ["httpx"],
    "nuclei": ["nuclei"],
    "rustscan": ["rustscan"],
    "naabu": ["naabu"],
    "ffuf": ["ffuf"],
}


class ReconnaissanceDetector:
    """Detects attacker reconnaissance and manages attacker profiles.

    This module is the trigger for the entire EPHEMERAL LABYRINTH system.
    When reconnaissance is detected, it activates the MirrorGraph and begins
    the deception campaign.
    """

    def __init__(self) -> None:
        self._attackers: dict[str, AttackerProfile] = {}
        self._connection_buffer: dict[str, list[tuple[float, int]]] = {}  # ip → [(timestamp, port)]
        self._dns_buffer: dict[str, list[float]] = {}  # ip → [timestamps]
        self._http_buffer: dict[str, list[float]] = {}  # ip → [timestamps]
        self._mirror_active: bool = False
        self._labyrinth_engine: Any = None  # set by LabyrinthController
        self._last_cleanup: float = time.time()
        self._cleanup_interval: float = 60.0  # seconds between cleanups
        self._buffer_ttl: float = 300.0  # 5 min TTL for buffer entries

    def _cleanup_stale_buffers(self) -> None:
        """Remove buffer entries older than _buffer_ttl to prevent unbounded growth."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - self._buffer_ttl
        # Clean connection buffer
        for ip in list(self._connection_buffer.keys()):
            self._connection_buffer[ip] = [(ts, p) for ts, p in self._connection_buffer[ip] if ts > cutoff]
            if not self._connection_buffer[ip]:
                del self._connection_buffer[ip]
        # Clean DNS buffer
        for ip in list(self._dns_buffer.keys()):
            self._dns_buffer[ip] = [ts for ts in self._dns_buffer[ip] if ts > cutoff]
            if not self._dns_buffer[ip]:
                del self._dns_buffer[ip]
        # Clean HTTP buffer
        for ip in list(self._http_buffer.keys()):
            self._http_buffer[ip] = [ts for ts in self._http_buffer[ip] if ts > cutoff]
            if not self._http_buffer[ip]:
                del self._http_buffer[ip]

    def set_labyrinth_engine(self, engine: Any) -> None:
        """Connect to the LabyrinthController for MirrorGraph activation."""
        self._labyrinth_engine = engine

    # ── EVENT INGESTION ───────────────────────────────────────────────

    def process_connection(self, source_ip: str, dest_port: int, protocol: str = "tcp") -> Optional[ReconEvent]:
        """Process a network connection event.

        Returns a ReconEvent if reconnaissance was detected, None otherwise.
        """
        now = time.time()
        self._cleanup_stale_buffers()

        # Buffer the connection
        if source_ip not in self._connection_buffer:
            self._connection_buffer[source_ip] = []
        self._connection_buffer[source_ip].append((now, dest_port))

        # Prune old entries
        self._connection_buffer[source_ip] = [
            (ts, port) for ts, port in self._connection_buffer[source_ip]
            if now - ts < PORT_SCAN_WINDOW
        ]

        # Check for port scan pattern
        connections = self._connection_buffer[source_ip]
        unique_ports = set(port for _, port in connections)
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            event = ReconEvent(
                event_id=f"recon_{int(now * 1000)}",
                recon_type=ReconType.PORT_SCAN,
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc),
                details={
                    "ports_scanned": sorted(unique_ports),
                    "port_count": len(unique_ports),
                    "window_seconds": PORT_SCAN_WINDOW,
                },
                severity="high",
                confidence=0.85,
            )
            self._handle_recon(event, source_ip)
            return event

        # Check for known sensitive ports being probed
        sensitive_ports = {22, 3306, 6379, 27017, 9200, 5601, 5432}
        if dest_port in sensitive_ports:
            event = ReconEvent(
                event_id=f"recon_{int(now * 1000)}",
                recon_type=ReconType.SERVICE_FINGERPRINT,
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc),
                details={"port": dest_port, "protocol": protocol},
                severity="medium",
                confidence=0.4,
            )
            self._handle_recon(event, source_ip)
            return event

        return None

    def process_dns(self, source_ip: str, query: str, query_type: str = "A") -> Optional[ReconEvent]:
        """Process a DNS query event."""
        now = time.time()
        self._cleanup_stale_buffers()

        if source_ip not in self._dns_buffer:
            self._dns_buffer[source_ip] = []
        self._dns_buffer[source_ip].append(now)

        # Prune
        self._dns_buffer[source_ip] = [
            ts for ts in self._dns_buffer[source_ip] if now - ts < DNS_ENUM_WINDOW
        ]

        if len(self._dns_buffer[source_ip]) >= DNS_ENUM_THRESHOLD:
            event = ReconEvent(
                event_id=f"recon_{int(now * 1000)}",
                recon_type=ReconType.DNS_ENUM,
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc),
                details={
                    "query": query,
                    "query_type": query_type,
                    "query_count": len(self._dns_buffer[source_ip]),
                    "window_seconds": DNS_ENUM_WINDOW,
                },
                severity="high",
                confidence=0.8,
            )
            self._handle_recon(event, source_ip)
            return event

        return None

    def process_http(self, source_ip: str, method: str, path: str, user_agent: str = "") -> Optional[ReconEvent]:
        """Process an HTTP request."""
        now = time.time()
        self._cleanup_stale_buffers()

        # Detect tool by User-Agent
        detected_tool = None
        ua_lower = user_agent.lower()
        for tool, signatures in TOOL_SIGNATURES.items():
            if any(sig.lower() in ua_lower for sig in signatures):
                detected_tool = tool
                break

        if detected_tool:
            event = ReconEvent(
                event_id=f"recon_{int(now * 1000)}",
                recon_type=ReconType.VULN_SCAN if "nikto" in detected_tool or "nuclei" in detected_tool else ReconType.WEB_CRAWL,
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc),
                details={
                    "method": method,
                    "path": path,
                    "user_agent": user_agent,
                    "detected_tool": detected_tool,
                },
                severity="critical" if detected_tool in ("sqlmap", "hydra", "nikto", "nuclei") else "high",
                confidence=0.95,
            )
            self._handle_recon(event, source_ip)
            return event

        # Buffer for web crawl detection
        if source_ip not in self._http_buffer:
            self._http_buffer[source_ip] = []
        self._http_buffer[source_ip].append(now)

        # Prune
        self._http_buffer[source_ip] = [
            ts for ts in self._http_buffer[source_ip] if now - ts < WEB_CRAWL_WINDOW
        ]

        if len(self._http_buffer[source_ip]) >= WEB_CRAWL_THRESHOLD:
            event = ReconEvent(
                event_id=f"recon_{int(now * 1000)}",
                recon_type=ReconType.WEB_CRAWL,
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc),
                details={
                    "method": method,
                    "path": path,
                    "request_count": len(self._http_buffer[source_ip]),
                },
                severity="high",
                confidence=0.75,
            )
            self._handle_recon(event, source_ip)
            return event

        return None

    def process_shell(self, source_ip: str, command: str) -> Optional[ReconEvent]:
        """Process a shell command."""
        recon_commands = ["nmap", "masscan", "whoami", "id", "uname", "ifconfig", "ip addr",
                          "cat /etc/passwd", "ls -la", "find", "netstat", "ss -", "lsof",
                          "curl", "wget", "nc ", "ncat", "enum4linux", "smbclient", "ldapsearch",
                          "getfacl", "sudo -l", "find / -perm"]

        cmd_lower = command.lower()
        for recon_cmd in recon_commands:
            if recon_cmd in cmd_lower:
                event = ReconEvent(
                    event_id=f"recon_{int(time.time() * 1000)}",
                    recon_type=ReconType.NETWORK_DISCOVERY if recon_cmd in ("netstat", "ss -", "nmap", "masscan") else ReconType.OS_FINGERPRINT,
                    source_ip=source_ip,
                    timestamp=datetime.now(timezone.utc),
                    details={"command": command, "matched_pattern": recon_cmd},
                    severity="critical" if recon_cmd in ("cat /etc/passwd", "sudo -l") else "high",
                    confidence=0.9,
                )
                self._handle_recon(event, source_ip)
                return event

        return None

    def process_auth(self, source_ip: str, username: str, success: bool, service: str = "ssh") -> Optional[ReconEvent]:
        """Process an authentication event."""
        if not success:
            # Failed auth — could be brute force
            event = ReconEvent(
                event_id=f"recon_{int(time.time() * 1000)}",
                recon_type=ReconType.CRED_DISCOVERY,
                source_ip=source_ip,
                timestamp=datetime.now(timezone.utc),
                details={
                    "username": username,
                    "service": service,
                    "success": success,
                },
                severity="high",
                confidence=0.7,
            )
            self._handle_recon(event, source_ip)
            return event
        return None

    # ── RECON HANDLING ───────────────────────────────────────────────

    def _handle_recon(self, event: ReconEvent, source_ip: str) -> None:
        """Handle a detected reconnaissance event."""
        # Get or create attacker profile
        if source_ip not in self._attackers:
            self._attackers[source_ip] = AttackerProfile(
                source_ip=source_ip,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )

        profile = self._attackers[source_ip]
        profile.last_seen = event.timestamp
        profile.recon_events.append(event)

        # Detect tools
        if event.details.get("detected_tool"):
            tool = event.details["detected_tool"]
            if tool not in profile.tools_detected:
                profile.tools_detected.append(tool)
                logger.warning(
                    "EPHEMERAL LABYRINTH: Attack tool detected — %s using %s",
                    source_ip, tool,
                )

        # Escalate threat level
        if event.recon_type == ReconType.PORT_SCAN and event.confidence > 0.8:
            profile.escalate(ThreatLevel.RECON)
        elif event.recon_type == ReconType.VULN_SCAN:
            profile.escalate(ThreatLevel.INTRUSION)
        elif event.severity == "critical":
            profile.escalate(ThreatLevel.CRITICAL)
        elif event.confidence > 0.7:
            profile.escalate(ThreatLevel.SUSPICIOUS)

        # Activate MirrorGraph if threat level is RECON or higher
        if profile.threat_level in (ThreatLevel.RECON, ThreatLevel.INTRUSION, ThreatLevel.CRITICAL):
            if not self._mirror_active:
                self._mirror_active = True
                logger.warning(
                    "EPHEMERAL LABYRINTH: ⚡ MirrorGraph ACTIVATED for attacker %s (threat: %s)",
                    source_ip, profile.threat_level.value,
                )
                if self._labyrinth_engine:
                    self._labyrinth_engine.on_recon_detected(profile)

    # ── PROFILE ACCESS ───────────────────────────────────────────────

    def get_attacker_profile(self, source_ip: str) -> Optional[AttackerProfile]:
        return self._attackers.get(source_ip)

    def get_all_attackers(self) -> list[AttackerProfile]:
        return list(self._attackers.values())

    @property
    def mirror_active(self) -> bool:
        return self._mirror_active

    def reset(self) -> None:
        """Reset all detection state (for testing or after engagement ends)."""
        self._attackers.clear()
        self._connection_buffer.clear()
        self._dns_buffer.clear()
        self._http_buffer.clear()
        self._mirror_active = False


# ── Singleton ────────────────────────────────────────────────────────────

_detector: Optional[ReconnaissanceDetector] = None


def get_recon_detector() -> ReconnaissanceDetector:
    global _detector
    if _detector is None:
        _detector = ReconnaissanceDetector()
    return _detector