"""Cerberus Vulnerability Library — stores and manages discovered vulnerabilities.

All findings stored in Neo4j as :ZeroDayFinding nodes.
Provides query, filtering, report generation, and export capabilities.

Academic basis:
- DARPA AIxCC (arXiv:2509.07225): automated vuln detection + reporting
- VulnLLM-R (arXiv:2512.07533): structured vulnerability documentation
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime
from typing import Any

from app.core.database import cypher_write, cypher_read

logger = logging.getLogger(__name__)


class VulnLibrary:
    """Stores and manages zero-day findings in Neo4j."""

    # ── Schema initialization ───────────────────────────────────────

    @staticmethod
    def init_schema() -> None:
        """Initialize Neo4j schema for zero-day findings."""
        statements = [
            "CREATE CONSTRAINT zeroday_finding_id IF NOT EXISTS FOR (z:ZeroDayFinding) REQUIRE z.finding_id IS UNIQUE",
            "CREATE INDEX zeroday_severity IF NOT EXISTS FOR (z:ZeroDayFinding) ON (z.severity)",
            "CREATE INDEX zeroday_target IF NOT EXISTS FOR (z:ZeroDayFinding) ON (z.target)",
            "CREATE INDEX zeroday_status IF NOT EXISTS FOR (z:ZeroDayFinding) ON (z.status)",
            "CREATE INDEX zeroday_discovered IF NOT EXISTS FOR (z:ZeroDayFinding) ON (z.discovered_at)",
        ]
        for stmt in statements:
            try:
                cypher_write(stmt)
            except Exception as e:
                logger.debug(f"Schema statement skipped: {e}")

    # ── CRUD operations ──────────────────────────────────────────────

    def add_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Store a new zero-day finding. Checks for duplicates.

        Args:
            finding: Finding data with fields:
                - target, vuln_type, cwe_class, severity, description
                - poc_code, stack_trace, campaign_id, signal, exit_code
        """
        finding_id = finding.get("finding_id") or f"ZD-{uuid.uuid4().hex[:8]}"
        discovered_at = finding.get("discovered_at") or datetime.now().isoformat()

        # Check for duplicate by stack trace hash or finding_id
        existing = cypher_read(
            "MATCH (z:ZeroDayFinding {finding_id: $finding_id}) RETURN z",
            {"finding_id": finding_id},
        )
        if existing:
            return {"status": "duplicate", "finding_id": finding_id, "message": "Finding already exists"}

        # Check by stack trace hash if available
        stack_hash = finding.get("stack_trace_hash", "")
        if stack_hash:
            existing_by_hash = cypher_read(
                "MATCH (z:ZeroDayFinding {stack_trace_hash: $hash}) RETURN z.finding_id AS id",
                {"hash": stack_hash},
            )
            if existing_by_hash:
                return {"status": "duplicate", "finding_id": existing_by_hash[0]["id"], "message": "Duplicate stack trace"}

        # Create the finding
        cypher_write(
            """
            CREATE (z:ZeroDayFinding {
                finding_id: $finding_id,
                target: $target,
                campaign_id: $campaign_id,
                vuln_type: $vuln_type,
                cwe_class: $cwe_class,
                cwe_name: $cwe_name,
                severity: $severity,
                description: $description,
                poc_code: $poc_code,
                stack_trace: $stack_trace,
                stack_trace_hash: $stack_trace_hash,
                signal: $signal,
                signal_name: $signal_name,
                exit_code: $exit_code,
                attack_techniques: $attack_techniques,
                exploitability: $exploitability,
                discovered_at: $discovered_at,
                status: 'new'
            })
            """,
            {
                "finding_id": finding_id,
                "target": finding.get("target", "unknown"),
                "campaign_id": finding.get("campaign_id", ""),
                "vuln_type": finding.get("vuln_type", "crash"),
                "cwe_class": finding.get("cwe_class", "CWE-20"),
                "cwe_name": finding.get("cwe_name", ""),
                "severity": finding.get("severity", "Low"),
                "description": finding.get("description", ""),
                "poc_code": finding.get("poc_code", ""),
                "stack_trace": finding.get("stack_trace", ""),
                "stack_trace_hash": stack_hash,
                "signal": finding.get("signal", 0),
                "signal_name": finding.get("signal_name", ""),
                "exit_code": finding.get("exit_code", 0),
                "attack_techniques": json.dumps(finding.get("attack_techniques", [])),
                "exploitability": finding.get("exploitability", "unknown"),
                "discovered_at": discovered_at,
            },
        )

        return {"status": "created", "finding_id": finding_id, "discovered_at": discovered_at}

    def get_findings(self, filter: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Query findings by severity, target, status, or date range.

        Args:
            filter: Optional dict with keys:
                - severity: "Critical" | "High" | "Medium" | "Low"
                - target: target string
                - status: "new" | "confirmed" | "reported" | "fixed"
                - date_from: ISO date string
                - date_to: ISO date string
                - limit: max results (default 100)
        """
        filter = filter or {}
        limit = filter.pop("limit", 100)

        conditions: list[str] = []
        params: dict[str, Any] = {"limit": limit}

        if "severity" in filter:
            conditions.append("z.severity = $severity")
            params["severity"] = filter["severity"]
        if "target" in filter:
            conditions.append("z.target CONTAINS $target")
            params["target"] = filter["target"]
        if "status" in filter:
            conditions.append("z.status = $status")
            params["status"] = filter["status"]
        if "date_from" in filter:
            conditions.append("z.discovered_at >= $date_from")
            params["date_from"] = filter["date_from"]
        if "date_to" in filter:
            conditions.append("z.discovered_at <= $date_to")
            params["date_to"] = filter["date_to"]

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"""
            MATCH (z:ZeroDayFinding)
            {where}
            RETURN z
            ORDER BY z.discovered_at DESC
            LIMIT $limit
        """

        results = cypher_read(query, params)
        findings = [r["z"] for r in results]
        # Deserialize attack_techniques
        for f in findings:
            if isinstance(f.get("attack_techniques"), str):
                try:
                    f["attack_techniques"] = json.loads(f["attack_techniques"])
                except (json.JSONDecodeError, TypeError):
                    f["attack_techniques"] = []
        return findings

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Get a specific finding by ID."""
        results = cypher_read(
            "MATCH (z:ZeroDayFinding {finding_id: $finding_id}) RETURN z",
            {"finding_id": finding_id},
        )
        if not results:
            return None
        finding = results[0]["z"]
        if isinstance(finding.get("attack_techniques"), str):
            try:
                finding["attack_techniques"] = json.loads(finding["attack_techniques"])
            except (json.JSONDecodeError, TypeError):
                finding["attack_techniques"] = []
        return finding

    def update_finding_status(self, finding_id: str, status: str) -> dict[str, Any]:
        """Update the status of a finding.

        Args:
            finding_id: The finding ID
            status: new status — "new", "confirmed", "reported", "fixed", "false_positive"
        """
        valid_statuses = {"new", "confirmed", "reported", "fixed", "false_positive"}
        if status not in valid_statuses:
            return {"error": f"Invalid status: {status}. Must be one of {valid_statuses}"}

        cypher_write(
            """
            MATCH (z:ZeroDayFinding {finding_id: $finding_id})
            SET z.status = $status, z.updated_at = $updated_at
            RETURN z
            """,
            {"finding_id": finding_id, "status": status, "updated_at": datetime.now().isoformat()},
        )

        return {"status": "updated", "finding_id": finding_id, "new_status": status}

    # ── Report generation ───────────────────────────────────────────

    def generate_report(self, finding_id: str) -> str:
        """Generate a formal vulnerability report in markdown.

        Args:
            finding_id: The finding ID

        Returns:
            Markdown formatted vulnerability report
        """
        finding = self.get_finding(finding_id)
        if not finding:
            return f"# Error\n\nFinding {finding_id} not found."

        # Parse attack techniques
        attack_techniques = finding.get("attack_techniques", [])
        if isinstance(attack_techniques, str):
            try:
                attack_techniques = json.loads(attack_techniques)
            except (json.JSONDecodeError, TypeError):
                attack_techniques = []

        # Severity emoji
        severity_emoji = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
        }.get(finding.get("severity", "Low"), "⚪")

        report = f"""# Vulnerability Report — {finding_id}

**Classification:** {severity_emoji} {finding.get('severity', 'Unknown')} Severity

## Summary

| Field | Value |
|-------|-------|
| **Finding ID** | {finding_id} |
| **Target** | `{finding.get('target', 'unknown')}` |
| **Vulnerability Type** | {finding.get('vuln_type', 'crash')} |
| **CWE Class** | {finding.get('cwe_class', 'CWE-20')} — {finding.get('cwe_name', 'Unknown')} |
| **Severity** | {finding.get('severity', 'Low')} |
| **Exploitability** | {finding.get('exploitability', 'unknown')} |
| **Status** | {finding.get('status', 'new')} |
| **Discovered** | {finding.get('discovered_at', 'unknown')} |

## Description

{finding.get('description', 'No description available.')}

## Technical Details

### Crash Information

| Field | Value |
|-------|-------|
| **Signal** | {finding.get('signal_name', 'N/A')} ({finding.get('signal', 'N/A')}) |
| **Exit Code** | {finding.get('exit_code', 'N/A')} |
| **Campaign ID** | {finding.get('campaign_id', 'N/A')} |

### Stack Trace

```
{finding.get('stack_trace', 'No stack trace available.')}
```

### MITRE ATT&CK Mapping

"""
        if attack_techniques:
            for technique in attack_techniques:
                report += f"- **{technique}** — Exploit technique\n"
        else:
            report += "- No ATT&CK techniques mapped\n"

        report += f"""
## Proof of Concept

> ⚠️ **DEFENSIVE VALIDATION ONLY** — This PoC is for reproducing and validating
> the vulnerability. It must NOT be used for exploitation or weaponization.

```
{finding.get('poc_code', 'No PoC available.')}
```

## Remediation Recommendations

1. **Input Validation:** Ensure all input is properly validated and bounded
2. **Boundary Checks:** Verify buffer sizes before write operations
3. **Error Handling:** Implement proper error handling for malformed input
4. **Testing:** Add regression tests based on this PoC
5. **Code Review:** Review the code path identified in the stack trace

## References

- **CWE:** {finding.get('cwe_class', 'CWE-20')} — {finding.get('cwe_name', 'Improper Input Validation')}
- **MITRE ATT&CK:** {', '.join(attack_techniques) if attack_techniques else 'N/A'}
- **Discovered by:** PITBULL Cerberus LLM-Guided Fuzzer
- **Discovery Date:** {finding.get('discovered_at', 'unknown')}

---

*This report was generated automatically by PITBULL Cerberus. All findings are
for defensive research purposes only.*
"""

        return report

    # ── Export ───────────────────────────────────────────────────────

    def export_findings(self, fmt: str = "json") -> str:
        """Export all findings in the specified format.

        Args:
            fmt: "json", "csv", or "md" (markdown)
        """
        findings = self.get_findings()

        if fmt == "json":
            return json.dumps(findings, indent=2, default=str)

        elif fmt == "csv":
            output = io.StringIO()
            if not findings:
                return "finding_id,target,vuln_type,cwe_class,severity,status,discovered_at\n"
            writer = csv.DictWriter(output, fieldnames=[
                "finding_id", "target", "vuln_type", "cwe_class", "cwe_name",
                "severity", "status", "discovered_at", "exploitability",
                "signal_name", "exit_code",
            ])
            writer.writeheader()
            for f in findings:
                row = {k: f.get(k, "") for k in writer.fieldnames}
                writer.writerow(row)
            return output.getvalue()

        elif fmt == "md":
            if not findings:
                return "# Zero-Day Findings\n\nNo findings to export.\n"

            lines = ["# PITBULL Cerberus — Zero-Day Findings Export\n"]
            lines.append(f"**Total Findings:** {len(findings)}\n")
            lines.append(f"**Exported:** {datetime.now().isoformat()}\n")
            lines.append("---\n")

            for f in findings:
                lines.append(f"## {f.get('finding_id', 'unknown')}")
                lines.append(f"- **Target:** `{f.get('target', 'unknown')}`")
                lines.append(f"- **Type:** {f.get('vuln_type', 'crash')}")
                lines.append(f"- **CWE:** {f.get('cwe_class', 'CWE-20')} — {f.get('cwe_name', '')}")
                lines.append(f"- **Severity:** {f.get('severity', 'Low')}")
                lines.append(f"- **Status:** {f.get('status', 'new')}")
                lines.append(f"- **Discovered:** {f.get('discovered_at', 'unknown')}")
                lines.append(f"- **Exploitability:** {f.get('exploitability', 'unknown')}")
                lines.append("")
            return "\n".join(lines)

        else:
            return json.dumps({"error": f"Unknown format: {fmt}"})

    # ── Analytics ───────────────────────────────────────────────────

    def get_analytics(self) -> dict[str, Any]:
        """Get analytics stats about findings."""
        findings = self.get_findings()

        # By severity
        by_severity: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "Unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # By CWE
        by_cwe: dict[str, int] = {}
        for f in findings:
            cwe = f.get("cwe_class", "CWE-20")
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

        # By target
        by_target: dict[str, int] = {}
        for f in findings:
            target = f.get("target", "unknown")
            by_target[target] = by_target.get(target, 0) + 1

        # By status
        by_status: dict[str, int] = {}
        for f in findings:
            status = f.get("status", "new")
            by_status[status] = by_status.get(status, 0) + 1

        # By date
        by_date: dict[str, int] = {}
        for f in findings:
            date = f.get("discovered_at", "")[:10]  # YYYY-MM-DD
            if date:
                by_date[date] = by_date.get(date, 0) + 1

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_cwe": by_cwe,
            "by_target": by_target,
            "by_status": by_status,
            "by_date": by_date,
            "critical_count": by_severity.get("Critical", 0),
            "high_count": by_severity.get("High", 0),
            "medium_count": by_severity.get("Medium", 0),
            "low_count": by_severity.get("Low", 0),
        }


# Singleton
_library: VulnLibrary | None = None


def get_library() -> VulnLibrary:
    """Get or create the VulnLibrary singleton."""
    global _library
    if _library is None:
        _library = VulnLibrary()
        _library.init_schema()
    return _library