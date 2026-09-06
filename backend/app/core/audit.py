"""PITBULL Audit Trail — hash-chained log of all actions.

Every action PITBULL takes is logged with a hash chain for forensic integrity.
This proves exactly what the agent did, when, and why.

Academic basis:
- Spoor (2026): hash-chained audit trail for forensic integrity
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import settings

logger = logging.getLogger(__name__)

AUDIT_FILE = Path(settings.state_dir) / "audit_chain.jsonl"


class AuditTrail:
    """Hash-chained audit log for all PITBULL actions."""

    def __init__(self):
        self.last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        """Get the hash of the last entry in the chain."""
        if not AUDIT_FILE.exists():
            return "0" * 64  # genesis hash
        last_hash = "0" * 64
        with open(AUDIT_FILE, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    last_hash = entry.get("hash", last_hash)
                except json.JSONDecodeError:
                    continue
        return last_hash

    def log_action(
        self,
        action_type: str,
        target: str = "",
        description: str = "",
        severity: str = "info",
        metadata: dict | None = None,
    ) -> dict[str, Any]:
        """Log an action to the audit chain."""
        timestamp = datetime.now().isoformat()
        prev_hash = self.last_hash

        entry_data = {
            "timestamp": timestamp,
            "action_type": action_type,
            "target": target,
            "description": description,
            "severity": severity,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
        }

        # Calculate hash of this entry
        entry_str = json.dumps(entry_data, sort_keys=True)
        entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()

        entry_data["hash"] = entry_hash
        self.last_hash = entry_hash

        # Append to chain
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry_data) + "\n")

        return entry_data

    def get_chain(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get the audit chain."""
        if not AUDIT_FILE.exists():
            return []
        entries = []
        with open(AUDIT_FILE, "r") as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return entries[-limit:]

    def verify_chain(self) -> dict[str, Any]:
        """Verify the integrity of the audit chain."""
        entries = self.get_chain(10000)
        prev_hash = "0" * 64
        valid = True
        broken_at = None

        for i, entry in enumerate(entries):
            stored_hash = entry.get("hash", "")
            stored_prev = entry.get("prev_hash", "")

            # Check chain link
            if stored_prev != prev_hash:
                valid = False
                broken_at = i
                break

            # Recompute hash
            entry_copy = {k: v for k, v in entry.items() if k != "hash"}
            entry_str = json.dumps(entry_copy, sort_keys=True)
            computed_hash = hashlib.sha256(entry_str.encode()).hexdigest()

            if computed_hash != stored_hash:
                valid = False
                broken_at = i
                break

            prev_hash = stored_hash

        return {
            "total_entries": len(entries),
            "valid": valid,
            "broken_at": broken_at,
            "last_hash": prev_hash if entries else "0" * 64,
        }

    def get_stats(self) -> dict[str, Any]:
        """Get audit trail statistics."""
        entries = self.get_chain(10000)
        type_counts: dict[str, int] = {}
        for e in entries:
            atype = e.get("action_type", "unknown")
            type_counts[atype] = type_counts.get(atype, 0) + 1

        return {
            "total_actions": len(entries),
            "by_type": type_counts,
            "chain_valid": self.verify_chain()["valid"],
        }


audit_trail = AuditTrail()