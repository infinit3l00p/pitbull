"""TrapCard Tool Analyzer — extracts strings, identifies file types, maps to MITRE ATT&CK.

Analyzes captured files for:
- File type identification (magic bytes)
- String extraction (first 100 unique strings > 4 chars)
- Pattern matching for known signatures (ELF, PE, Mach-O, scripts)
- MITRE ATT&CK technique mapping based on content
- Stores analysis results on :ToolSample nodes in Neo4j
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import struct
from pathlib import Path
from typing import Any

from datetime import datetime, timezone
import math

from app.core.database import cypher_write

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK signature patterns ──────────────────────────────

ATTACK_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    # technique_id: [(pattern, description), ...]
    "T1046": [  # Network Scan
        (r"\bnmap\b", "nmap network scanner"),
        (r"\bmasscan\b", "masscan port scanner"),
        (r"\bzmap\b", "zmap fast scanner"),
        (r"\bzgrab\b", "zgrab scanner"),
        (r"\brustscan\b", "rustscan scanner"),
        (r"\bnaabu\b", "naabu port scanner"),
    ],
    "T1003": [  # OS Credential Dumping
        (r"\bmimikatz\b", "mimikatz credential dumper"),
        (r"\blsass\b", "lsass process access"),
        (r"\bprocdump\b", "procdump memory dump"),
        (r"\bregistry\b.*\bSAM\b", "SAM registry hive access"),
        (r"\bsecretsdump\b", "impacket secretsdump"),
    ],
    "T1110": [  # Brute Force
        (r"\bhydra\b", "hydra brute force tool"),
        (r"\bmedusa\b", "medusa brute force tool"),
        (r"\bpatator\b", "patato brute force tool"),
        (r"\bncrack\b", "ncrack brute force tool"),
        (r"\bhashcat\b", "hashcat password cracker"),
        (r"\bjohn\b.*\bripper\b", "john the ripper password cracker"),
    ],
    "T1059": [  # Command and Scripting Interpreter
        (r"#!/usr/bin/python", "python script"),
        (r"#!/usr/bin/perl", "perl script"),
        (r"#!/bin/bash", "bash script"),
        (r"#!/bin/sh", "shell script"),
        (r"#!/usr/bin/env ruby", "ruby script"),
        (r"\bpowershell\b", "powershell script"),
    ],
    "T1078": [  # Valid Accounts
        (r"\bsshpass\b", "sshpass credential tool"),
        (r"\bcredentials?\b", "credential reference"),
        (r"\bpassword\b.*\blist\b", "password list reference"),
    ],
    "T1190": [  # Exploit Public-Facing Application
        (r"\bsqlmap\b", "sqlmap injection tool"),
        (r"\bmetasploit\b", "metasploit framework"),
        (r"\bmsfconsole\b", "metasploit console"),
        (r"\bexploit\b.*\bdb\b", "exploit database reference"),
        (r"\bsearchsploit\b", "exploit-db searchsploit"),
    ],
    "T1505": [  # Server Software Component
        (r"\bwebshell\b", "webshell reference"),
        (r"\bc99\.php\b", "c99 webshell"),
        (r"\bb374k\b", "b374k webshell"),
        (r"\bwso\b", "WSO webshell"),
    ],
    "T1547": [  # Boot or Logon Autostart Execution
        (r"\bcrontab\b", "crontab persistence"),
        (r"\bsystemctl\b.*\benable\b", "systemd persistence"),
        (r"\b\.bashrc\b", "bashrc persistence"),
        (r"\b\.profile\b", "profile persistence"),
    ],
    "T1571": [  # Non-Standard Port
        (r"\bnc\b.*\b-l\b.*\b-p\b", "netcat listener"),
        (r"\bncat\b.*\b-l\b", "ncat listener"),
        (r"\bsocat\b", "socat relay"),
    ],
    "T1059": [  # Command and Scripting Interpreter (add python3)
        (r"#!/usr/bin/python", "python script"),
        (r"#!/usr/bin/perl", "perl script"),
        (r"#!/bin/bash", "bash script"),
        (r"#!/bin/sh", "shell script"),
        (r"#!/usr/bin/env ruby", "ruby script"),
        (r"#!/bin/python", "python script"),
        (r"\bpowershell\b", "powershell script"),
    ],
    "T1105": [  # Ingress Tool Transfer
        (r"\bsocket\.connect\b", "socket connection"),
        (r"\bSOCK_STREAM\b", "TCP socket"),
        (r"\bdup2\b.*\bfileno\b", "file descriptor duplication"),
        (r"\brecv\b.*\bsend\b", "recv/send pattern"),
    ],
    "T1055": [  # Process Injection
        (r"\bptrace\b", "ptrace injection"),
        (r"\bLD_PRELOAD\b", "LD_PRELOAD injection"),
        (r"\bdlopen\b", "dynamic library loading"),
    ],
    "T1560": [  # Archive Collected Data
        (r"\btar\b.*\bczf\b", "tar archive creation"),
        (r"\bzip\b.*\b-r\b", "zip archive creation"),
        (r"\b7z\b", "7zip archive"),
        (r"\bgzip\b", "gzip compression"),
    ],
    "T1041": [  # Exfiltration Over C2 Channel
        (r"\bcurl\b.*\bhttp", "curl exfiltration"),
        (r"\bwget\b.*\bhttp", "wget exfiltration"),
        (r"\bscp\b", "scp exfiltration"),
        (r"\brsync\b", "rsync exfiltration"),
    ],
    "T1087": [  # Account Discovery
        (r"\bwhoami\b", "whoami identity check"),
        (r"\bid\b", "id command"),
        (r"\busers?\b.*\blist\b", "user enumeration"),
        (r"\bnet\b.*\buser\b", "windows user enumeration"),
        (r"\bgetent\b.*\bpasswd\b", "passwd enumeration"),
    ],
    "T1083": [  # File and Directory Discovery
        (r"\bfind\b.*\b/", "filesystem search"),
        (r"\bls\b.*\b-la\b", "directory listing"),
        (r"\btree\b", "directory tree"),
        (r"\bdir\b.*\b/s\b", "windows recursive dir"),
    ],
    "T1068": [  # Exploitation for Privilege Escalation
        (r"\bsudo\b", "sudo privilege escalation"),
        (r"\bsu\b.*\broot\b", "su to root"),
        (r"\bpkexec\b", "pkexec exploitation"),
        (r"\bdirty\b.*\bcow\b", "dirty cow exploit"),
    ],
    "T1027": [  # Obfuscated Files or Information
        (r"\bbase64\b.*\bdecode\b", "base64 decoding"),
        (r"\bbase64\b.*\bencode\b", "base64 encoding"),
        (r"\bxor\b.*\bdecrypt\b", "XOR decryption"),
        (r"\brot13\b", "ROT13 obfuscation"),
    ],
    "T1071": [  # Application Layer Protocol
        (r"\bhttp\b.*\bproxy\b", "HTTP proxy"),
        (r"\bsocks5\b", "SOCKS5 proxy"),
        (r"\bsocks4\b", "SOCKS4 proxy"),
    ],
    "T1486": [  # Data Encrypted for Impact
        (r"\bransomware\b", "ransomware reference"),
        (r"\bencrypt\b.*\bfiles?\b", "file encryption"),
        (r"\bdecrypt\b.*\binstruction\b", "decryption instructions"),
    ],
}

# ── Magic bytes database ──────────────────────────────────────────

MAGIC_BYTES: list[tuple[bytes, str, str]] = [
    # (magic, file_type, description)
    (b"\x7fELF", "elf", "ELF executable"),
    (b"MZ", "pe", "Windows PE executable"),
    (b"\xcf\xfa\xed\xfe", "mach-o-64", "Mach-O 64-bit executable"),
    (b"\xfe\xed\xfa\xce", "mach-o-32", "Mach-O 32-bit executable"),
    (b"\xca\xfe\xba\xbe", "mach-o-fat", "Mach-O fat binary"),
    (b"PK\x03\x04", "zip", "ZIP archive"),
    (b"PK\x05\x06", "zip-empty", "Empty ZIP archive"),
    (b"\x1f\x8b", "gzip", "Gzip compressed"),
    (b"BZh", "bzip2", "Bzip2 compressed"),
    (b"\xfd7z\x5a\x58", "xz", "XZ compressed"),
    (b"\x28\xb5\x2f\xfd", "zstd", "Zstandard compressed"),
    (b"Rar!", "rar", "RAR archive"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"GIF87a", "gif87", "GIF image (87a)"),
    (b"GIF89a", "gif89", "GIF image (89a)"),
    (b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (b"BM", "bmp", "BMP image"),
    (b"\x25\x50\x44\x46", "pdf", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "ole2", "OLE2 document"),
    (b"\x50\x4b\x03\x04", "office-zip", "Office Open XML"),
    (b"\x00\x00\x01\x00", "ico", "Windows icon"),
    (b"\x00\x00\x02\x00", "cur", "Windows cursor"),
    (b"\x42\x5a\x68", "bzip2-old", "Bzip2 compressed (old)"),
    (b"\x37\x7a\xbc\xaf", "7z", "7zip archive"),
    (b"\x04\x22\x4d\x18", "lz4", "LZ4 compressed"),
    (b"\x28\xb5\x2f\xfd", "zstd", "Zstandard compressed"),
]

# Script shebangs
SCRIPT_SHEBANGS: list[tuple[str, str]] = [
    ("#!/usr/bin/env python", "python"),
    ("#!/usr/bin/python", "python"),
    ("#!/usr/bin/env python3", "python3"),
    ("#!/usr/bin/python3", "python3"),
    ("#!/bin/python", "python"),
    ("#!/bin/python3", "python3"),
    ("#!/usr/bin/env python2", "python2"),
    ("#!/usr/bin/perl", "perl"),
    ("#!/usr/bin/env perl", "perl"),
    ("#!/bin/bash", "bash"),
    ("#!/bin/sh", "sh"),
    ("#!/usr/bin/env bash", "bash"),
    ("#!/usr/bin/env ruby", "ruby"),
    ("#!/usr/bin/ruby", "ruby"),
    ("#!/usr/bin/env node", "nodejs"),
    ("#!/usr/bin/node", "nodejs"),
    ("#!/usr/bin/env php", "php"),
    ("#!/usr/bin/php", "php"),
    ("#!/usr/bin/lua", "lua"),
    ("#!/usr/bin/env lua", "lua"),
]


def _extract_strings(data: bytes, min_length: int = 5, max_strings: int = 100) -> list[str]:
    """Extract printable strings from binary data.

    Returns first max_strings unique strings of at least min_length characters.
    """
    strings: list[str] = []
    seen: set[str] = set()

    # Try to find ASCII strings
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    for match in pattern.finditer(data):
        s = match.group().decode("ascii", errors="replace").strip()
        if s and s not in seen:
            seen.add(s)
            strings.append(s)
            if len(strings) >= max_strings:
                break

    # If we need more, try UTF-16 strings
    if len(strings) < max_strings:
        utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
        for match in utf16_pattern.finditer(data):
            try:
                s = match.group().decode("utf-16-le", errors="replace").strip()
                if s and s not in seen:
                    seen.add(s)
                    strings.append(s)
                    if len(strings) >= max_strings:
                        break
            except Exception:
                continue

    return strings


def _identify_file_type(data: bytes) -> dict[str, str]:
    """Identify file type from magic bytes."""
    # Check magic bytes
    for magic, ftype, desc in MAGIC_BYTES:
        if data.startswith(magic):
            return {"type": ftype, "description": desc, "method": "magic"}

    # Check shebang for scripts
    if len(data) > 2 and data[:2] == b"#!":
        try:
            first_line = data.split(b"\n", 1)[0].decode("ascii", errors="replace")
            for shebang, script_type in SCRIPT_SHEBANGS:
                if shebang in first_line:
                    return {"type": script_type, "description": f"Script: {first_line}", "method": "shebang"}
        except Exception:
            pass
        return {"type": "shellscript", "description": "Shell script", "method": "shebang"}

    # Check for common text patterns
    try:
        text = data.decode("utf-8")
        if "<?xml" in text[:100]:
            return {"type": "xml", "description": "XML document", "method": "content"}
        if "<html" in text[:200].lower():
            return {"type": "html", "description": "HTML document", "method": "content"}
        if text.startswith("{") and text.rstrip().endswith("}"):
            return {"type": "json", "description": "JSON document", "method": "content"}
        if "-----BEGIN" in text[:100]:
            return {"type": "pem", "description": "PEM certificate/key", "method": "content"}
        # Plain text
        return {"type": "text", "description": "Plain text", "method": "content"}
    except (UnicodeDecodeError, Exception):
        pass

    return {"type": "unknown", "description": "Unknown binary format", "method": "unknown"}


def _match_attack_techniques(strings: list[str], file_type: str) -> list[dict[str, str]]:
    """Match file content against MITRE ATT&CK technique signatures.

    Returns list of {technique_id, description, matched_pattern} dicts.
    """
    # Combine all strings into a single searchable text
    text = "\n".join(strings).lower()
    techniques: list[dict[str, str]] = []
    seen_techniques: set[str] = set()

    for technique_id, patterns in ATTACK_SIGNATURES.items():
        if technique_id in seen_techniques:
            continue
        for pattern_str, description in patterns:
            try:
                if re.search(pattern_str, text, re.IGNORECASE):
                    techniques.append({
                        "technique_id": technique_id,
                        "description": description,
                        "matched_pattern": pattern_str,
                    })
                    seen_techniques.add(technique_id)
                    break
            except re.error:
                continue

    # Also check file type for script-based techniques
    if file_type in ("python", "python3", "bash", "sh", "perl", "ruby", "php", "nodejs"):
        if "T1059" not in seen_techniques:
            techniques.append({
                "technique_id": "T1059",
                "description": f"{file_type} script interpreter",
                "matched_pattern": f"file_type={file_type}",
            })
            seen_techniques.add("T1059")

    return techniques


def _check_yara_like(data: bytes, strings: list[str]) -> list[dict[str, str]]:
    """YARA-like pattern matching for known malware signatures."""
    signatures: list[dict[str, str]] = []
    text = "\n".join(strings)

    # Check for known malware families
    malware_families = {
        "mirai": r"\bmirai\b",
        "mozi": r"\bmozi\b",
        "botnet": r"\bbotnet\b",
        "c2_server": r"\bc2\b.*\bserver\b",
        "reverse_shell": r"\b/bin/sh\b.*\b-i\b",
        "bind_shell": r"\bnc\b.*\b-l\b.*\b-p\b",
        "crypto_miner": r"\bxmrig\b",
        "crypto_miner2": r"\bstratum\b.*\bpool\b",
        "keylogger": r"\bkeylog\b",
        "rootkit": r"\brootkit\b",
        "backdoor": r"\bbackdoor\b",
        "trojan": r"\btrojan\b",
        "worm": r"\bworm\b",
        "ransomware": r"\bransom\b",
    }

    for name, pattern in malware_families.items():
        try:
            if re.search(pattern, text, re.IGNORECASE):
                signatures.append({
                    "family": name,
                    "pattern": pattern,
                    "description": f"Matched signature: {name}",
                })
        except re.error:
            continue

    return signatures


def analyze_file(file_path: str) -> dict[str, Any]:
    """Analyze a captured file.

    Args:
        file_path: Path to the file to analyze.

    Returns:
        Analysis dict with file_type, strings, attack_techniques, signatures, etc.
    """
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    data = path.read_bytes()

    # Basic info
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)

    # File type identification
    file_type_info = _identify_file_type(data)

    # String extraction
    strings = _extract_strings(data, min_length=5, max_strings=100)

    # MITRE ATT&CK mapping
    attack_techniques = _match_attack_techniques(strings, file_type_info["type"])

    # YARA-like signature matching
    signatures = _check_yara_like(data, strings)

    # Entropy estimation (simple)
    if size > 0:
        byte_freq: list[int] = [0] * 256
        for b in data[:65536]:  # Sample first 64KB
            byte_freq[b] += 1
        entropy = 0.0
        sample_size = min(size, 65536)
        for freq in byte_freq:
            if freq > 0:
                p = freq / sample_size
                entropy -= p * math.log2(p)
    else:
        entropy = 0.0

    analysis: dict[str, Any] = {
        "sha256": sha256,
        "size": size,
        "file_type": file_type_info["type"],
        "file_type_description": file_type_info["description"],
        "identification_method": file_type_info["method"],
        "strings": strings,
        "string_count": len(strings),
        "attack_techniques": attack_techniques,
        "signatures": signatures,
        "entropy": round(entropy, 4),
        "is_script": file_type_info["type"] in ("python", "python3", "bash", "sh", "perl", "ruby", "php", "nodejs", "shellscript"),
        "is_binary": file_type_info["type"] in ("elf", "pe", "mach-o-64", "mach-o-32", "mach-o-fat"),
        "is_archive": file_type_info["type"] in ("zip", "gzip", "bzip2", "xz", "zstd", "rar", "7z", "tar"),
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Store analysis on ToolSample node in Neo4j
    try:
        cypher_write(
            """
            MATCH (t:ToolSample {sha256: $sha256})
            SET t.analysis = $analysis,
                t.attack_techniques = $technique_ids,
                t.file_type = $file_type,
                t.entropy = $entropy,
                t.is_script = $is_script,
                t.is_binary = $is_binary,
                t.analyzed_at = $analyzed_at
            """,
            {
                "sha256": sha256,
                "analysis": __import__("json").dumps(analysis),
                "technique_ids": [t["technique_id"] for t in attack_techniques],
                "file_type": file_type_info["type"],
                "entropy": round(entropy, 4),
                "is_script": analysis["is_script"],
                "is_binary": analysis["is_binary"],
                "analyzed_at": analysis["analyzed_at"],
            },
        )
        logger.info(
            "TrapCard: analyzed %s — type=%s, techniques=%d, signatures=%d",
            path.name, file_type_info["type"], len(attack_techniques), len(signatures),
        )
    except Exception as e:
        logger.error("TrapCard: failed to store analysis in Neo4j: %s", e)

    return analysis