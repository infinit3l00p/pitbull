"""Sentinel Log Monitor — real-time log tailing for SSH, nginx, and journald.

Tails /var/log/auth.log, /var/log/nginx/access.log, and journalctl output,
parsing log lines into structured events for the attack detector.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Log paths ──────────────────────────────────────────────────────
AUTH_LOG = "/var/log/auth.log"
NGINX_ACCESS_LOG = "/var/log/nginx/access.log"

# ── Regex patterns ─────────────────────────────────────────────────

# SSH: "Jul 20 19:27:01 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2"
_SSH_FAILED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?P<user_type>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) "
    r"port (?P<port>\d+)"
)

# SSH: "Accepted password for user from 1.2.3.4 port 54321 ssh2"
_SSH_ACCEPTED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) "
    r"port (?P<port>\d+)"
)

# SSH: "Invalid user admin from 1.2.3.4 port 54321"
_SSH_INVALID_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid user (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) "
    r"port (?P<port>\d+)"
)

# nginx access log: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
_NGINX_RE = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)

# Suspicious user agents — expanded with modern recon/exploitation tools
SUSPICIOUS_UA = {
    # Network scanners
    "nmap", "masscan", "zgrab", "zmap", "naabu", "rustscan",
    # Web scanners
    "nikto", "dirb", "gobuster", "ffuf", "feroxbuster", "wfuzz",
    "wpscan", "nuclei", "httpx", "katana", "crawlergo", "subfinder",
    "amass", "assetfinder", "subjs", "gauplus", "waybackurls",
    # Exploitation frameworks
    "sqlmap", "metasploit", "burp", "burpsuite", "acunetix",
    "nessus", "openvas", "arachni", "skipfish", "w3af", "commix",
    # Credential attacks
    "hydra", "medusa", "ncrack", "patator", "thc-hydra",
    # Proxies/automation
    "aria2", "python-requests", "go-http-client", "scrapy",
    "httpx-go", "req_url", "okhttp", "libwww-perl",
    # Mobile/reverse engineering
    "frida", "objection", "mobf",
    # Bots that don't belong
    "semrushbot", "mj12bot", "ahrefsbot",  # SEO crawlers — suspicious on an API server
}

# SQL injection patterns in URL — expanded
SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.I),
    re.compile(r"or\s+1\s*=\s*1", re.I),
    re.compile(r"and\s+1\s*=\s*1", re.I),
    re.compile(r"'\s*or\s*'", re.I),
    re.compile(r"select\s+.*\s+from", re.I),
    re.compile(r"insert\s+into", re.I),
    re.compile(r"drop\s+table", re.I),
    re.compile(r"--\s*$", re.I),
    re.compile(r"information_schema", re.I),
    re.compile(r"sleep\s*\(", re.I),
    re.compile(r"benchmark\s*\(", re.I),
    re.compile(r"load_file\s*\(", re.I),
    re.compile(r"concat\s*\(", re.I),
    re.compile(r"0x[0-9a-f]+\s*=\s*0x[0-9a-f]+", re.I),  # hex comparison
    re.compile(r"extractvalue\s*\(", re.I),  # XML-based SQLi
    re.compile(r"updatexml\s*\(", re.I),  # XML-based SQLi
    re.compile(r"procedure\s+analyse\s*\(", re.I),
    re.compile(r"outfile\s+['\"]", re.I),  # file write
    re.compile(r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}", re.I),  # hex-encoded payloads
    re.compile(r"%27|%22", re.I),  # URL-encoded quotes
]

# XSS patterns in URL
XSS_PATTERNS = [
    re.compile(r"<script", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"onerror\s*=", re.I),
    re.compile(r"onload\s*=", re.I),
    re.compile(r"onclick\s*=", re.I),
    re.compile(r"onmouseover\s*=", re.I),
    re.compile(r"onfocus\s*=", re.I),
    re.compile(r"<img\s+[^>]*src\s*=", re.I),
    re.compile(r"<svg\s+[^>]*onload", re.I),
    re.compile(r"<iframe", re.I),
    re.compile(r"<object", re.I),
    re.compile(r"<embed", re.I),
    re.compile(r"alert\s*\(", re.I),
    re.compile(r"document\.cookie", re.I),
    re.compile(r"document\.location", re.I),
    re.compile(r"window\.location", re.I),
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"String\.fromCharCode", re.I),
    re.compile(r"%3Cscript", re.I),  # URL-encoded <script
    re.compile(r"%3Cimg", re.I),  # URL-encoded <img
    re.compile(r"%3Csvg", re.I),  # URL-encoded <svg
]

# Command injection patterns
CMDI_PATTERNS = [
    re.compile(r";\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|nc|python|perl)\b", re.I),
    re.compile(r"\|\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|nc|python|perl)\b", re.I),
    re.compile(r"&&\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|nc|python|perl)\b", re.I),
    re.compile(r"\|\|\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|nc|python|perl)\b", re.I),
    re.compile(r"`[^`]+`"),  # backtick execution
    re.compile(r"\$\([^)]+\)"),  # $(...) execution
    re.compile(r"%0a", re.I),  # URL-encoded newline
    re.compile(r"%0d", re.I),  # URL-encoded carriage return
    re.compile(r"\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}", re.I),  # hex escape sequences
]

# XXE (XML External Entity) patterns
XXE_PATTERNS = [
    re.compile(r"<!ENTITY", re.I),
    re.compile(r"<!DOCTYPE.*ENTITY", re.I),
    re.compile(r"SYSTEM\s+['\"]file://", re.I),
    re.compile(r"SYSTEM\s+['\"]http://", re.I),
    re.compile(r"%\s*\w+\s*;", re.I),  # parameter entity
    re.compile(r"<!\[CDATA\[", re.I),
]

# SSRF patterns
SSRF_PATTERNS = [
    re.compile(r"url\s*=\s*['\"]?file://", re.I),
    re.compile(r"url\s*=\s*['\"]?http://169\.254\.169\.254", re.I),  # AWS metadata
    re.compile(r"url\s*=\s*['\"]?http://localhost", re.I),
    re.compile(r"url\s*=\s*['\"]?http://127\.0\.0\.1", re.I),
    re.compile(r"redirect\s*=\s*['\"]?http://169\.254", re.I),
    re.compile(r"target\s*=\s*['\"]?http://169\.254", re.I),
    re.compile(r"webhook\s*=\s*['\"]?http://169\.254", re.I),
    re.compile(r"169\.254\.169\.254", re.I),  # cloud metadata anywhere in URL
    re.compile(r"metadata\.google\.internal", re.I),  # GCP metadata
]

# Path traversal patterns
TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"/proc/self"),
    re.compile(r"%2e%2e%2f", re.I),
    re.compile(r"%2e%2e/", re.I),
]

# Sensitive file access patterns — expanded
SENSITIVE_FILES = [
    "/.env", "/.git/", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/wp-admin", "/wp-login", "/wp-config", "/xmlrpc.php",
    "/admin", "/administrator", "/phpmyadmin", "/admin.php",
    "/.ssh/", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/.htaccess", "/.htpasswd",
    "/config.php", "/config.json", "/config.yml", "/config.yaml",
    "/backup", "/db.sql", "/dump.sql",
    "/api/v1/users", "/api/keys", "/api/v1/api-keys", "/api/v1/tokens",
    "/server-status", "/server-info",
    # Cloud/infra metadata
    "/.aws/credentials", "/.aws/config",
    "/.docker/", "/docker-compose.yml", "/docker-compose.yaml",
    "/.gitlab-ci.yml", "/Jenkinsfile",
    "/.npmrc", "/.pypirc", "/.netrc",
    "/id_rsa", "/id_ecdsa", "/id_ed25519",
    "/.kube/config", "/.kube/token",
    "/.terraform", "/terraform.tfstate",
    "/.vscode/", "/.idea/",
    "/.bash_history", "/.zsh_history", "/.python_history",
    "/.lesshst", "/.mysql_history", "/.psql_history",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt",
    "/Procfile", "/.procfile",
    "/.capistrano", "/.ansible",
]

# Web shell patterns — file extensions that shouldn't be served
WEB_SHELL_PATTERNS = [
    re.compile(r"\.(php|php5|php7|phtml|pht)\b", re.I),  # PHP shells
    re.compile(r"\.(jsp|jspx|war)\b", re.I),  # Java shells
    re.compile(r"\.(asp|aspx|ashx|asax)\b", re.I),  # ASP.NET shells
    re.compile(r"\.(sh|bash|zsh)\b", re.I),  # shell scripts
    re.compile(r"\.(py|pl|rb|cgi)\b", re.I),  # script uploads
]

# Known web shell names
WEB_SHELL_NAMES = {
    "c99.php", "r57.php", "b374k.php", "wso.php", "shell.php",
    "cmd.php", "c.php", "1.php", "0x.php", "indoxploit.php",
    "webshell.php", "backdoor.php", "hack.php", "up.php",
    "alfaware.php", "ws.php", "unknown.php", "x.php",
    "shell.jsp", "cmd.jsp", "shell.asp", "cmd.asp",
    "cmdsh.php", "ddos.php", "ddos.sh",
}

# HTTP methods that are suspicious on non-API routes
SUSPICIOUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

# ── Event structure ────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ssh_timestamp(ts: str) -> str:
    """Parse syslog timestamp (e.g. 'Jul 20 19:27:01') into ISO format."""
    try:
        dt = datetime.strptime(ts, "%b %d %H:%M:%S")
        dt = dt.replace(year=datetime.now().year, tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return _now_iso()


def _parse_nginx_timestamp(ts: str) -> str:
    """Parse nginx timestamp (e.g. '20/Jul/2026:19:27:01 +0000') into ISO format."""
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        return _now_iso()


class LogMonitor:
    """Async log monitor that tails multiple log sources and emits structured events."""

    def __init__(self, event_callback: Any = None) -> None:
        self.event_callback = event_callback
        self._running = False
        self._tasks: list[asyncio.Task] = []
        # In-memory ring buffer: last 1000 events per source
        self._buffers: dict[str, deque] = {
            "ssh": deque(maxlen=1000),
            "nginx": deque(maxlen=1000),
            "journal": deque(maxlen=1000),
        }

    async def start(self) -> None:
        """Start all log monitoring tasks."""
        self._running = True
        self._tasks = [
            asyncio.create_task(self._tail_ssh(), name="sentinel-ssh"),
            asyncio.create_task(self._tail_nginx(), name="sentinel-nginx"),
            asyncio.create_task(self._tail_journal(), name="sentinel-journal"),
        ]
        logger.info("Sentinel LogMonitor started — tailing %s, %s, journalctl", AUTH_LOG, NGINX_ACCESS_LOG)

    async def stop(self) -> None:
        """Stop all monitoring tasks."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Sentinel LogMonitor stopped")

    def get_buffer(self, source: str) -> list[dict]:
        """Return buffered events for a source."""
        return list(self._buffers.get(source, deque()))

    # ── SSH log tailing ───────────────────────────────────────────

    async def _tail_ssh(self) -> None:
        """Tail /var/log/auth.log for SSH events."""
        await self._tail_file(
            AUTH_LOG,
            self._parse_ssh_line,
            "ssh",
        )

    # ── nginx log tailing ────────────────────────────────────────

    async def _tail_nginx(self) -> None:
        """Tail nginx access log for web attack events."""
        await self._tail_file(
            NGINX_ACCESS_LOG,
            self._parse_nginx_line,
            "nginx",
        )

    # ── journalctl tailing ──────────────────────────────────────

    async def _tail_journal(self) -> None:
        """Tail journalctl for systemd-level security events."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "journalctl", "-f", "-n", "0", "--output=short",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout is not None
            logger.info("Sentinel: journalctl stream opened")
            while self._running:
                line = await proc.stdout.readline()
                if not line:
                    await asyncio.sleep(1)
                    continue
                event = self._parse_journal_line(line.decode("utf-8", errors="replace").strip())
                if event:
                    self._emit(event, "journal")
        except FileNotFoundError:
            logger.warning("journalctl not available — journal monitoring disabled")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Sentinel journal monitor error: %s", e)

    # ── File tailing utility ─────────────────────────────────────

    async def _tail_file(
        self,
        path: str,
        parser: Any,
        source: str,
    ) -> None:
        """Generic async file tailer that calls parser on each new line."""
        while self._running:
            try:
                # Seek to end on first open
                f = open(path, "r", encoding="utf-8", errors="replace")
                f.seek(0, 2)  # end of file
                logger.info("Sentinel: tailing %s", path)
                while self._running:
                    line = f.readline()
                    if not line:
                        await asyncio.sleep(1)
                        continue
                    event = parser(line.strip())
                    if event:
                        self._emit(event, source)
                f.close()
            except FileNotFoundError:
                logger.warning("Sentinel: %s not found — retrying in 5s", path)
                await asyncio.sleep(5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Sentinel error tailing %s: %s", path, e)
                await asyncio.sleep(5)

    # ── Parsers ──────────────────────────────────────────────────

    def _parse_ssh_line(self, line: str) -> dict | None:
        """Parse an auth.log line into a structured SSH event."""
        # Failed password (includes invalid users)
        m = _SSH_FAILED_RE.search(line)
        if m:
            is_invalid = bool(m.group("user_type"))
            return {
                "timestamp": _parse_ssh_timestamp(m.group("ts")),
                "source_ip": m.group("ip"),
                "event_type": "ssh_failed_login" if not is_invalid else "ssh_invalid_user",
                "details": {
                    "user": m.group("user"),
                    "port": int(m.group("port")),
                    "invalid_user": is_invalid,
                },
            }

        # Accepted password
        m = _SSH_ACCEPTED_RE.search(line)
        if m:
            return {
                "timestamp": _parse_ssh_timestamp(m.group("ts")),
                "source_ip": m.group("ip"),
                "event_type": "ssh_accepted",
                "details": {
                    "user": m.group("user"),
                    "port": int(m.group("port")),
                },
            }

        # Invalid user (may appear separately from Failed password)
        m = _SSH_INVALID_RE.search(line)
        if m:
            return {
                "timestamp": _parse_ssh_timestamp(m.group("ts")),
                "source_ip": m.group("ip"),
                "event_type": "ssh_invalid_user",
                "details": {
                    "user": m.group("user"),
                    "port": int(m.group("port")),
                },
            }

        return None

    def _parse_nginx_line(self, line: str) -> dict | None:
        """Parse an nginx access log line into a structured web event."""
        m = _NGINX_RE.match(line)
        if not m:
            return None

        ip = m.group("ip")
        status = int(m.group("status"))
        method = m.group("method")
        url = m.group("url")
        ua = m.group("ua")
        ts = _parse_nginx_timestamp(m.group("ts"))

        event: dict[str, Any] = {
            "timestamp": ts,
            "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
            "event_type": "web_request",
            "details": {
                "method": method,
                "url": url,
                "status": status,
                "user_agent": ua,
                "referer": m.group("referer"),
            },
        }

        # Classify the event with sub-types
        tags: list[str] = []

        # Check status code
        if status >= 500:
            tags.append("server_error")
        elif status == 404:
            tags.append("not_found")
        elif status >= 400:
            tags.append("client_error")

        # Check for suspicious user agents
        ua_lower = ua.lower()
        for suspect in SUSPICIOUS_UA:
            if suspect in ua_lower:
                tags.append("suspicious_ua")
                event["details"]["suspected_tool"] = suspect
                break

        # Check for SQL injection patterns
        for pattern in SQLI_PATTERNS:
            if pattern.search(url):
                tags.append("sqli_attempt")
                break

        # Check for XSS patterns
        for pattern in XSS_PATTERNS:
            if pattern.search(url):
                tags.append("xss_attempt")
                break

        # Check for command injection
        for pattern in CMDI_PATTERNS:
            if pattern.search(url):
                tags.append("cmdi_attempt")
                break

        # Check for XXE
        for pattern in XXE_PATTERNS:
            if pattern.search(url):
                tags.append("xxe_attempt")
                break

        # Check for SSRF
        for pattern in SSRF_PATTERNS:
            if pattern.search(url):
                tags.append("ssrf_attempt")
                break

        # Check for path traversal
        for pattern in TRAVERSAL_PATTERNS:
            if pattern.search(url):
                tags.append("path_traversal")
                break

        # Check for sensitive file access
        url_lower = url.lower()
        for sensitive in SENSITIVE_FILES:
            if sensitive in url_lower:
                tags.append("sensitive_file_access")
                event["details"]["sensitive_path"] = sensitive
                break

        # Check for web shell access (known names)
        url_path = url.split("?")[0]  # strip query string
        url_filename = url_path.rstrip("/").split("/")[-1] if "/" in url_path else url_path
        if url_filename.lower() in WEB_SHELL_NAMES:
            tags.append("web_shell_access")
            event["details"]["web_shell"] = url_filename

        # Check for suspicious HTTP methods on non-API routes
        if method in SUSPICIOUS_METHODS and not url.startswith("/api/"):
            tags.append("method_abuse")
            event["details"]["suspicious_method"] = method

        # Check for login endpoints (for credential stuffing)
        if method == "POST" and any(
            ep in url_lower for ep in ("/login", "/signin", "/auth", "/api/login", "/api/auth")
        ):
            tags.append("login_attempt")

        # Check for API key/token enumeration (multiple /api/* 401/403s)
        if url.startswith("/api/") and status in (401, 403):
            tags.append("api_auth_failure")

        if tags:
            event["tags"] = tags

        return event

    def _parse_journal_line(self, line: str) -> dict | None:
        """Parse a journalctl line for systemd-level security events."""
        # Look for interesting systemd events
        if not line:
            return None

        # Failed services, sudo attempts, etc.
        # Only match actual systemd service failures, not arbitrary log lines containing "failed"
        if re.search(r'systemd\[1\]:.*(?:Failed|failed).*(?:service|result|exit)', line) or \
           re.search(r'systemd\[1\]:.*: (?:Failed|failed)', line):
            # Skip our own services to avoid feedback loops
            if any(svc in line for svc in ['pitbull.service', 'vigil.service', 'attacksurface.service',
                                           'identity-proxy.service', 'ai-agent']):
                return None
            # Try to extract an IP if present
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else None
            return {
                "timestamp": _now_iso(),
                "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
                "event_type": "system_failure",
                "details": {"raw": line[:500]},
            }

        if "sudo:" in line and "authentication failure" in line.lower():
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else None
            user_match = re.search(r"sudo:\s+(\S+)\s+:\s+.*authentication failure", line)
            user = user_match.group(1) if user_match else "unknown"
            return {
                "timestamp": _now_iso(),
                "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
                "event_type": "sudo_failure",
                "details": {"raw": line[:500], "user": user},
            }

        # ── User creation / modification (T1098 Account Manipulation) ──
        if re.search(r'useradd\[\d+\]:\s+new user', line, re.I) or \
           re.search(r'usermod\[\d+\]:\s+add', line, re.I) or \
           re.search(r'adduser\[\d+\]:\s+new user', line, re.I):
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else None
            user_match = re.search(r'(?:user|name)[:\s]+(\S+)', line)
            user = user_match.group(1) if user_match else "unknown"
            return {
                "timestamp": _now_iso(),
                "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
                "event_type": "user_creation",
                "details": {"raw": line[:500], "user": user},
            }

        # ── Cron / systemd timer tampering (T1053.003 Cron) ──
        if re.search(r'crontab\[\d+\]:\s+.*(?:replaced|updated|install)', line, re.I) or \
           re.search(r'systemd\[1\]:\s+.*timer.*changed', line, re.I):
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else None
            return {
                "timestamp": _now_iso(),
                "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
                "event_type": "cron_tampering",
                "details": {"raw": line[:500]},
            }

        # ── Log clearing / tampering (T1070.002 Clear Logs) ──
        if re.search(r'journalctl.*--vacuum', line, re.I) or \
           re.search(r'/var/log/.*(?:truncated|deleted|removed)', line, re.I) or \
           re.search(r'rm\s+.*(?:auth\.log|syslog|messages|secure)', line, re.I) or \
           re.search(r'cat\s+.*>\s*.*(?:auth\.log|syslog)', line, re.I):
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else None
            return {
                "timestamp": _now_iso(),
                "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
                "event_type": "log_tampering",
                "details": {"raw": line[:500]},
            }

        # ── Firewall tampering (T1562.001 Disable Tools) ──
        if re.search(r'ufw\[\d+\]:\s+.*(?:disable|reset)', line, re.I) or \
           re.search(r'iptables\[\d+\]:\s+.*(?:-F|--flush|-D)', line, re.I) or \
           re.search(r'fail2ban.*(?:stopped|shutdown)', line, re.I):
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else None
            return {
                "timestamp": _now_iso(),
                "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
                "event_type": "firewall_tampering",
                "details": {"raw": line[:500]},
            }

        # ── Process crash / segfault (potential exploit) ──
        if re.search(r'segfault at.*ip.*sp.*error', line, re.I) or \
           re.search(r'Killed process.*pid.*out-of-memory', line, re.I):
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            ip = ip_match.group(1) if ip_match else None
            proc_match = re.search(r'Killed process.*(\d+) \(([^)]+)\)', line)
            proc_name = proc_match.group(2) if proc_match else "unknown"
            return {
                "timestamp": _now_iso(),
                "source_ip": ip or "0.0.0.0",  # local system event — no remote attacker
                "event_type": "process_crash",
                "details": {"raw": line[:500], "process": proc_name},
            }

        return None

    # ── Event emission ───────────────────────────────────────────

    def _emit(self, event: dict, source: str) -> None:
        """Store event in ring buffer and forward to callback."""
        self._buffers[source].append(event)
        if self.event_callback:
            try:
                self.event_callback(event, source)
            except Exception as e:
                logger.error("Sentinel event callback error: %s", e)