"""TrapCard SSH Honeypot — async TCP server simulating an SSH service.

Presents a fake SSH banner, accepts any credentials, and provides a fake shell
with LLM-generated responses. Captures attacker files (wget/curl downloads,
scp uploads) and records entire sessions.

Uses Ollama at http://127.0.0.1:11434 with model "qwen2.5:7b" (primary),
"glm-5.2:cloud" (fallback).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.config import settings
from app.trapcard.capture import capture_file

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────

SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
CAPTURE_BASE = Path("/opt/pitbull/captured_tools")
SESSION_LOG_BASE = Path("/opt/pitbull/captured_tools/ssh_sessions")

# LLM models
PRIMARY_MODEL = "qwen2.5:7b"
FALLBACK_MODEL = "qwen2.5:7b"  # LOCAL ONLY

# Fake filesystem for the simulated shell
FAKE_FILESYSTEM = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "opt", "proc", "root", "run", "sbin", "srv", "tmp", "usr", "var"],
    "/home": ["ubuntu", "admin", "user", "test"],
    "/root": [".bashrc", ".bash_history", ".ssh", ".profile", ".cache", ".config"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "resolv.conf", "ssh", "crontab", "group"],
    "/tmp": [".X11-unix", "systemd-private-1234", "snap-private"],
    "/var": ["log", "lib", "cache", "spool", "tmp", "www"],
    "/var/www": ["html", "index.html", "config.php"],
    "/var/log": ["auth.log", "syslog", "nginx", "dmesg"],
    "/usr": ["bin", "lib", "local", "share", "include"],
    "/usr/local": ["bin", "lib", "etc"],
    "/opt": ["app", "docker", "miniconda3"],
}

FAKE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
    "/etc/hostname": "ubuntu-web-01\n",
    "/etc/hosts": "127.0.0.1 localhost\n127.0.1.1 ubuntu-web-01\n",
    "/root/.bashrc": "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\nalias ll='ls -la'\n",
    "/root/.profile": "# ~/.profile\nif [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n        . \"$HOME/.bashrc\"\n    fi\nfi\n",
    "/var/www/index.html": "<html><body><h1>Welcome to Ubuntu</h1></body></html>\n",
    "/var/www/config.php": "<?php\n$db_host = 'localhost';\n$db_user = 'webapp';\n$db_pass = 's3cr3t_p@ss';\n$db_name = 'production';\n?>\n",
}

# ── LLM Shell ─────────────────────────────────────────────────────


class LLMShell:
    """LLM-powered fake shell response generator."""

    def __init__(self) -> None:
        self.base_url = settings.llm_base_url
        self._local_available: bool | None = None
        self.client = httpx.Client()

    def _check_local_model(self) -> bool:
        """Check if qwen2.5:7b is available."""
        if self._local_available is not None:
            return self._local_available
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                self._local_available = any(m.get("name") == PRIMARY_MODEL for m in models)
        except Exception:
            self._local_available = False
        return self._local_available

    def _get_model(self) -> str:
        """Get the model to use — local first, cloud fallback."""
        if self._check_local_model():
            return PRIMARY_MODEL
        return FALLBACK_MODEL

    def generate_response(self, command: str, cwd: str, username: str) -> str:
        """Generate a realistic shell response using LLM."""
        system_prompt = (
            f"You are simulating a Linux shell on an Ubuntu 22.04 server. "
            f"The current user is '{username}' with root-like privileges. "
            f"Current directory: {cwd}. "
            f"Respond with ONLY the command output (no explanations, no markdown). "
            f"Keep responses realistic and concise. "
            f"If the command is unknown, respond with 'bash: command not found'. "
            f"If the command would produce no output (like cd, export, setting variables), respond with empty string."
        )

        try:
            resp = self.client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self._get_model(),
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": command},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.7, "num_predict": 200},
                },
                timeout=20.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("message", {}).get("content", "").strip()
                return content
        except Exception as e:
            logger.debug("TrapCard SSH: LLM error: %s", e)

        # Fallback to built-in command handler
        return self._builtin_response(command, cwd, username)

    def _builtin_response(self, command: str, cwd: str, username: str) -> str:
        """Built-in fallback command handler."""
        cmd = command.strip().split()
        if not cmd:
            return ""
        base = cmd[0]

        if base == "ls":
            path = cwd
            if len(cmd) > 1 and not cmd[1].startswith("-"):
                path = cmd[-1]
            files = FAKE_FILESYSTEM.get(path, [])
            return "  ".join(files)

        if base == "whoami":
            return username

        if base == "id":
            return f"uid=0({username}) gid=0({username}) groups=0({username}),27(sudo)"

        if base == "pwd":
            return cwd

        if base == "uname":
            if "-a" in command:
                return "Linux ubuntu-web-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
            return "Linux"

        if base == "cat":
            if len(cmd) > 1:
                fname = cmd[-1]
                return FAKE_FILES.get(fname, f"cat: {fname}: No such file or directory")
            return ""

        if base == "echo":
            return " ".join(cmd[1:]).replace("$USER", username).replace("$HOME", f"/home/{username}")

        if base == "hostname":
            return "ubuntu-web-01"

        if base == "ifconfig" or base == "ip":
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255"

        return f"bash: {base}: command not found"


# ── SSH Honeypot Server ───────────────────────────────────────────


class SSHHoneypot:
    """Async SSH honeypot server singleton."""

    _instance: SSHHoneypot | None = None

    def __new__(cls) -> SSHHoneypot:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self._running = False
        self._server: asyncio.Server | None = None
        self._port: int = 2222
        self._host: str = "0.0.0.0"
        self._sessions: dict[str, dict] = {}  # session_id -> session info
        self._active_connections: int = 0
        self._total_connections: int = 0
        self._shell = LLMShell()

        # SSE subscriber queues
        self._subscribers: list[asyncio.Queue] = []

    # ── Lifecycle ───────────────────────────────────────────────

    async def start(self, port: int = 2222, host: str = "0.0.0.0") -> dict[str, Any]:
        """Start the SSH honeypot server."""
        if self._running:
            return {"success": False, "error": "Already running"}

        self._port = port
        self._host = host

        try:
            self._server = await asyncio.start_server(
                self._handle_connection, host, port,
            )
            self._running = True
            logger.info("TrapCard SSH honeypot started on %s:%d", host, port)
            return {"success": True, "port": port, "host": host}
        except Exception as e:
            logger.error("TrapCard SSH: failed to start: %s", e)
            return {"success": False, "error": str(e)}

    async def stop(self) -> dict[str, Any]:
        """Stop the SSH honeypot server."""
        if not self._running:
            return {"success": False, "error": "Not running"}

        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        logger.info("TrapCard SSH honeypot stopped")
        return {"success": True}

    def is_running(self) -> bool:
        return self._running

    def get_status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "port": self._port,
            "host": self._host,
            "active_connections": self._active_connections,
            "total_connections": self._total_connections,
            "total_sessions": len(self._sessions),
        }

    def get_sessions(self) -> list[dict]:
        return list(self._sessions.values())

    def get_session(self, session_id: str) -> dict | None:
        return self._sessions.get(session_id)

    # ── SSE ─────────────────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    def _push_event(self, data: dict) -> None:
        for q in self._subscribers:
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(data)
                except Exception:
                    pass

    # ── Connection handler ─────────────────────────────────────

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle a single SSH connection."""
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "unknown"
        client_port = peer[1] if peer else 0

        session_id = str(uuid.uuid4())
        self._active_connections += 1
        self._total_connections += 1

        # Create session log
        SESSION_LOG_BASE.mkdir(parents=True, exist_ok=True)
        log_path = SESSION_LOG_BASE / f"{session_id}.log"
        log_entries: list[str] = []

        def log_session(msg: str) -> None:
            ts = datetime.now(timezone.utc).isoformat()
            entry = f"[{ts}] {msg}"
            log_entries.append(entry)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(entry + "\n")

        log_session(f"Connection from {client_ip}:{client_port}")
        self._push_event({
            "type": "ssh_connect",
            "session_id": session_id,
            "source_ip": client_ip,
            "port": client_port,
            "timestamp": time.time(),
        })

        # Session state
        session_info: dict[str, Any] = {
            "session_id": session_id,
            "source_ip": client_ip,
            "source_port": client_port,
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "username": "unknown",
            "commands": [],
            "files_captured": 0,
            "log_path": str(log_path),
            "service": "ssh",
        }

        try:
            # Send SSH banner
            writer.write(SSH_BANNER.encode())
            await writer.drain()

            # Read SSH client banner
            try:
                client_banner = await asyncio.wait_for(reader.readline(), timeout=10.0)
                log_session(f"Client banner: {client_banner.decode('utf-8', errors='replace').strip()}")
            except asyncio.TimeoutError:
                log_session("Client banner timeout — continuing anyway")

            # Simulate SSH key exchange / auth negotiation
            # We accept any credentials — send a fake auth success
            await self._simulate_auth(writer, reader, client_ip, session_id, log_session, session_info)

            # Store session in Neo4j
            from app.core.database import cypher_write
            try:
                cypher_write(
                    """
                    MERGE (s:AttackerSession {session_id: $session_id})
                    SET s.source_ip = $source_ip,
                        s.service = 'ssh',
                        s.first_seen = $first_seen,
                        s.last_seen = $first_seen,
                        s.log_path = $log_path
                    """,
                    {
                        "session_id": session_id,
                        "source_ip": client_ip,
                        "first_seen": session_info["connected_at"],
                        "log_path": str(log_path),
                    },
                )
            except Exception as e:
                logger.debug("TrapCard SSH: Neo4j session store: %s", e)

            # Enter fake shell
            await self._fake_shell(writer, reader, client_ip, session_id, log_session, session_info)

        except (ConnectionResetError, BrokenPipeError):
            log_session("Connection reset by peer")
        except asyncio.CancelledError:
            log_session("Connection cancelled")
        except Exception as e:
            log_session(f"Error: {e}")
        finally:
            self._active_connections -= 1
            session_info["disconnected_at"] = datetime.now(timezone.utc).isoformat()
            session_info["duration"] = time.time() - time.mktime(
                datetime.fromisoformat(session_info["connected_at"]).timetuple()
            )
            self._sessions[session_id] = session_info

            log_session("Session ended")
            self._push_event({
                "type": "ssh_disconnect",
                "session_id": session_id,
                "source_ip": client_ip,
                "timestamp": time.time(),
            })

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Auth simulation ─────────────────────────────────────────

    async def _simulate_auth(
        self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader,
        client_ip: str, session_id: str, log_session, session_info: dict,
    ) -> None:
        """Simulate SSH authentication — accept any credentials."""
        # Send a simplified SSH auth prompt
        # In a real SSH protocol, this would be binary key exchange
        # We simplify: just present a login prompt

        writer.write(b"login: ")
        await writer.drain()

        try:
            username_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            username = username_line.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            username = "root"

        writer.write(b"Password: ")
        await writer.drain()

        try:
            # Read password (might not echo in real SSH, but we simplify)
            password_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            password = password_line.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            password = ""

        log_session(f"Auth attempt: username='{username}', password='{password}'")
        session_info["username"] = username
        session_info["password"] = password

        self._push_event({
            "type": "ssh_auth",
            "session_id": session_id,
            "source_ip": client_ip,
            "username": username,
            "password": password,
            "timestamp": time.time(),
        })

        # Accept credentials
        writer.write(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        writer.write(b" * Documentation:  https://help.ubuntu.com\r\n")
        writer.write(b" * Management:     https://landscape.canonical.com\r\n")
        writer.write(b" * Support:        https://ubuntu.com/advantage\r\n\r\n")
        writer.write(f"{username}@ubuntu-web-01:~$ ".encode())
        await writer.drain()

    # ── Fake shell ──────────────────────────────────────────────

    async def _fake_shell(
        self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader,
        client_ip: str, session_id: str, log_session, session_info: dict,
    ) -> None:
        """Provide a fake interactive shell."""
        cwd = f"/home/{session_info.get('username', 'user')}"
        username = session_info.get("username", "root")
        prompt = f"{username}@ubuntu-web-01:{cwd}$ "

        while True:
            try:
                # Read command line
                line = await asyncio.wait_for(reader.readline(), timeout=300.0)
                command = line.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                log_session("Shell idle timeout — closing connection")
                break
            except (ConnectionResetError, BrokenPipeError):
                break

            if not command:
                writer.write(prompt.encode())
                await writer.drain()
                continue

            log_session(f"CMD: {command}")
            session_info["commands"].append(command)

            self._push_event({
                "type": "ssh_command",
                "session_id": session_id,
                "source_ip": client_ip,
                "command": command,
                "timestamp": time.time(),
            })

            # Handle built-in commands first
            response, should_exit, captured = await self._handle_command(
                command, cwd, username, client_ip, session_id, writer, reader, log_session, session_info,
            )

            if captured:
                session_info["files_captured"] = session_info.get("files_captured", 0) + 1

            if response:
                writer.write((response + "\r\n").encode("utf-8", errors="replace"))
                log_session(f"RESP: {response[:200]}")

            if should_exit:
                log_session("Client requested exit")
                break

            # Update prompt with cwd
            prompt = f"{username}@ubuntu-web-01:{cwd}$ "
            writer.write(prompt.encode())
            await writer.drain()

    async def _handle_command(
        self, command: str, cwd: str, username: str,
        client_ip: str, session_id: str,
        writer: asyncio.StreamWriter, reader: asyncio.StreamReader,
        log_session, session_info: dict,
    ) -> tuple[str, bool, bool]:
        """Handle a single shell command. Returns (response, should_exit, file_captured)."""
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return ("", False, False)

        base = cmd_parts[0]
        should_exit = False
        file_captured = False

        # ── exit / quit ──
        if base in ("exit", "quit", "logout"):
            return ("logout", True, False)

        # ── cd ──
        if base == "cd":
            target = cmd_parts[1] if len(cmd_parts) > 1 else f"/home/{username}"
            # Simplified cd — just update cwd
            if target.startswith("/"):
                cwd = target
            else:
                cwd = f"{cwd.rstrip('/')}/{target}"
            # Normalize
            cwd = os.path.normpath(cwd)
            return ("", False, False)

        # ── wget / curl — capture downloaded files ──
        if base in ("wget", "curl"):
            url = None
            output_file = None
            for i, arg in enumerate(cmd_parts):
                if arg.startswith("http://") or arg.startswith("https://") or arg.startswith("ftp://"):
                    url = arg
                if arg == "-o" and i + 1 < len(cmd_parts):
                    output_file = cmd_parts[i + 1]
                if arg == "-O":
                    output_file = url.split("/")[-1] if url else "download"

            if url:
                log_session(f"Download attempt: {url}")
                # Try to actually download the file (for capture purposes)
                try:
                    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                        resp = await client.get(url)
                        file_data = resp.content
                        filename = output_file or url.split("/")[-1] or "downloaded_file"

                        # Capture the file
                    metadata = capture_file(
                        file_data=file_data,
                        source_ip=client_ip,
                        service="ssh",
                        session_id=session_id,
                        filename=filename,
                    )
                    log_session(f"Captured file: {filename} ({len(file_data)} bytes, sha256={metadata['sha256'][:16]})")
                    file_captured = True

                    self._push_event({
                        "type": "file_captured",
                        "session_id": session_id,
                        "source_ip": client_ip,
                        "service": "ssh",
                        "filename": filename,
                        "sha256": metadata["sha256"],
                        "size": metadata["size"],
                        "timestamp": time.time(),
                    })

                    return (f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving host... done.\nConnecting... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: {len(file_data)} [{metadata['mime_type']}]\nSaving to: '{filename}'\n\n{filename} 100%[===================>] {len(file_data)}  --.-KB/s    in 0s\n\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} URL: {url} [{len(file_data)}] -> \"{filename}\" [1]", False, True)
                except Exception as e:
                    log_session(f"Download failed: {e}")
                    return (f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving host... failed: Temporary failure in name resolution.\nwget: unable to resolve host address", False, False)
            else:
                return ("Usage: wget [OPTION]... [URL]...\nTry `wget --help' for more options.", False, False)

        # ── scp — capture uploaded files ──
        if base == "scp":
            log_session(f"SCP attempt: {command}")
            return ("scp: connection closed by remote host", False, False)

        # ── python / perl / ruby — capture scripts ──
        if base in ("python", "python3", "perl", "ruby", "node", "php"):
            # Check if it's a file execution
            if len(cmd_parts) > 1:
                script_file = cmd_parts[-1]
                if not script_file.startswith("-"):
                    log_session(f"Script execution: {base} {script_file}")
                    # Check if the file exists in our fake filesystem
                    # In real scenario, attacker might paste a script — we'd capture it
                    return (f"{base}: can't open file '{script_file}': [Errno 2] No such file or directory", False, False)

            # Interactive mode — simulate
            return (f"Python 3.10.12 (main, Jun 11 2023, 05:26:16) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>> ", False, False)

        # ── base64 decode — capture decoded data ──
        if base == "base64" and "decode" in command:
            # This is a common exfiltration technique
            log_session(f"Base64 decode attempt: {command}")
            return ("", False, False)

        # ── LLM-generated response for everything else ──
        response = await asyncio.get_event_loop().run_in_executor(
            None, self._shell.generate_response, command, cwd, username,
        )
        return (response, False, False)


# ── Module-level singleton ────────────────────────────────────────

ssh_honeypot = SSHHoneypot()