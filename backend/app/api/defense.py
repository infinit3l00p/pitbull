"""PITBULL API — Defense endpoints.

Endpoints for active defense operations including RAM Zero
(memory hygiene), DMA protection monitoring, and MAC sync status.

ATT&CK Mapping: T1070 (Indicator Removal), T1562 (Impair Defenses)
"""

from __future__ import annotations

import asyncio
import time
import json
import logging
import subprocess
import os
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(tags=["defense"])
public_router = APIRouter(tags=["defense"])

# ── State ────────────────────────────────────────────────────────────
_ram_zero_state: dict[str, Any] = {
    "last_run": None,
    "last_status": None,
    "total_runs": 0,
    "total_freed_kb": 0,
    "history": [],
}
_max_history = 100


class RamZeroReport(BaseModel):
    status: str = Field(..., description="Status of the RAM flush")
    detail: str = Field(..., description="Details about the flush")
    freed_kb: int = Field(0, description="KB of memory freed")
    timestamp: int = Field(..., description="Unix timestamp of the report")


@public_router.get("/defense/ram-zero/status")
async def ram_zero_status() -> dict[str, Any]:
    """Get RAM Zero monitor status."""
    # Read current memory state
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.strip().split(":")
                if len(parts) == 2:
                    meminfo[parts[0]] = int(parts[1].strip().rstrip(" kB"))
    except Exception:
        meminfo = {}

    # Check if systemd service is active
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "ram-zero.timer"],
            capture_output=True, text=True, timeout=3,
        )
        service_active = result.stdout.strip() == "active"
    except Exception:
        service_active = False

    return {
        "name": "RAM Zero",
        "description": "Memory hygiene flush — reduces DMA extraction window",
        "service_active": service_active,
        "last_run": _ram_zero_state["last_run"],
        "last_status": _ram_zero_state["last_status"],
        "total_runs": _ram_zero_state["total_runs"],
        "total_freed_kb": _ram_zero_state["total_freed_kb"],
        "current_memory": {
            "total_kb": meminfo.get("MemTotal", 0),
            "available_kb": meminfo.get("MemAvailable", 0),
            "free_kb": meminfo.get("MemFree", 0),
            "cached_kb": meminfo.get("Cached", 0),
            "slab_kb": meminfo.get("Slab", 0),
            "swap_total_kb": meminfo.get("SwapTotal", 0),
            "swap_free_kb": meminfo.get("SwapFree", 0),
        },
        "history": _ram_zero_state["history"][-20:],
    }


@router.post("/defense/ram-zero/report")
async def ram_zero_report(report: RamZeroReport) -> dict[str, Any]:
    """Receive a report from the RAM Zero script."""
    _ram_zero_state["last_run"] = report.timestamp
    _ram_zero_state["last_status"] = report.status
    _ram_zero_state["total_runs"] += 1
    _ram_zero_state["total_freed_kb"] += report.freed_kb
    _ram_zero_state["history"].append({
        "timestamp": report.timestamp,
        "status": report.status,
        "detail": report.detail,
        "freed_kb": report.freed_kb,
    })
    if len(_ram_zero_state["history"]) > _max_history:
        _ram_zero_state["history"].pop(0)
    return {"received": True}


@router.post("/defense/ram-zero/trigger")
async def ram_zero_trigger() -> dict[str, Any]:
    """Manually trigger a RAM Zero flush."""
    try:
        proc = subprocess.run(
            ["/usr/local/bin/ram-zero.sh", "now"],  # example path — configure for your setup
            capture_output=True, text=True, timeout=120,
        )
        return {
            "status": "ok" if proc.returncode == 0 else "error",
            "output": proc.stdout[-2000:] if proc.stdout else "",
            "exit_code": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": "RAM Zero took too long"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ── ME DMA Protection Status ─────────────────────────────────────────
@public_router.get("/defense/dma-protection/status")
async def dma_protection_status() -> dict[str, Any]:
    """Get ME DMA protection status."""
    try:
        with open("/sys/kernel/iommu_groups/9/type") as f:
            iommu_type = f.read().strip()
    except Exception:
        iommu_type = "unknown"

    # Check internal WiFi
    try:
        with open("/sys/class/net/wlo1/carrier") as f:
            wlo1_carrier = f.read().strip()
    except Exception:
        wlo1_carrier = "0"

    # Check if driver is bound
    driver_bound = os.path.exists("/sys/bus/pci/devices/0000:01:00.0/driver")

    return {
        "name": "ME DMA Protection",
        "iommu_mode": iommu_type,
        "internal_wifi": {
            "interface": "wlo1",
            "carrier": wlo1_carrier,
            "driver_bound": driver_bound,
            "status": "DOWN" if wlo1_carrier == "0" else "UP ⚠️",
        },
        "usb_wifi": {
            "interface": os.environ.get("DEFENSE_IFACE", "wlan0"),
            "driver": "ath9k_htc",
            "status": "active (ME-free path)",
        },
    }


# ── MAC Sync Status ──────────────────────────────────────────────────
@public_router.get("/defense/mac-sync/status")
async def mac_sync_status() -> dict[str, Any]:
    """Get MAC sync status — projected MAC vs actual WiFi MAC."""
    import re
    IFACE = os.environ.get("DEFENSE_IFACE", "wlan0")

    try:
        with open(f"/sys/class/net/{IFACE}/address") as f:
            current_mac = f.read().strip().upper()
    except Exception:
        current_mac = "unknown"

    # Get the identity-projected MAC.
    # The projector writes no MAC values to journald (identity values in logs
    # leak the exact projected identity to any local user in adm). The
    # authoritative source is the root-only state file written by the identity
    # projector on every projection.
    # PRIMARY: state file. SECONDARY: legacy journald "MAC=" lines (older
    # builds). LAST RESORT: OUI-only from /profiles (cannot ever compare equal).
    proj_mac = None
    rotation_count = 0
    try:
        with open(os.environ.get("PROJECTED_MAC_FILE", "/run/projected_mac")) as f:
            m = re.search(r"mac=([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", f.read())
            if m:
                proj_mac = m.group(1).upper()
    except Exception:
        pass

    # Rotation count from the (valueless) journald event lines — the event
    # marker still identifies every projection; only the MAC value is gone.
    try:
        result = subprocess.run(
            ["journalctl", "-u", os.environ.get("IDENTITY_PROXY_UNIT", "identity-proxy"), "--since", "2 hours ago", "--no-pager", "-o", "cat"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "identity projected" in line:
                rotation_count += 1
                # legacy projector builds carried the MAC on the same line
                if not proj_mac and "MAC=" in line:
                    m = re.search(r"MAC=([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", line)
                    if m:
                        proj_mac = m.group(1).upper()
    except Exception:
        pass

    # Get identity profile info (fallback for OUI)
    proj_profile = None
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:8442/profiles", timeout=3) as resp:
            import json as _json
            profiles = _json.loads(resp.read())
            for p in profiles:
                if p.get("current"):
                    proj_profile = p.get("id", "")
                    if not proj_mac:
                        # Fallback: use OUI from profile
                        oui = p.get("mac_oui", "").upper()
                        if oui:
                            proj_mac = f"{oui} (OUI only)"
                    break
    except Exception:
        pass

    # Get last sync from mac-sync state file
    last_sync = None
    try:
        with open("/var/run/mac-sync-state.json") as f:
            last_sync = json.loads(f.read())
    except Exception:
        pass

    # Get permanent MAC (hardware) from ip link output
    perm_mac = None
    try:
        result = subprocess.run(
            ["ip", "link", "show", IFACE],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"permaddr\s+([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", result.stdout)
        if m:
            perm_mac = m.group(1).upper()
    except Exception:
        pass

    synced = (current_mac == proj_mac) if proj_mac and "OUI only" not in proj_mac else False

    return {
        "name": "MAC Sync",
        "current_mac": current_mac,
        "projected_mac": proj_mac,
        "synced": synced,
        "interface": IFACE,
        "permanent_mac": perm_mac,
        "projected_profile": proj_profile,
        "rotation_count_2h": rotation_count,
        "last_sync": last_sync,
    }

# ── RAM Poison — Anti-Forensic Decoy Injector ────────────────────────
@public_router.get("/defense/ram-poison/status")
async def ram_poison_status() -> dict[str, Any]:
    """Get RAM Poison decoy injector status."""
    stats = {}
    for attempt in range(3):
        try:
            with open("/var/run/ram-poison-stats.json") as f:
                raw = f.read()
            stats = json.loads(raw)
            logger.warning(f"RAM POISON: read {len(raw)} bytes, decoys={stats.get('total_decoys', 0)}")
            if stats.get("total_decoys", 0) > 0:
                break
        except Exception:
            pass
        import time as _time
        _time.sleep(0.1)
    if not stats:
        stats = {"running": False, "total_decoys": 0, "total_bytes": 0}

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "ram-poison.service"],
            capture_output=True, text=True, timeout=3,
        )
        service_active = result.stdout.strip() == "active"
    except Exception:
        service_active = False

    return {
        "name": "RAM Poison",
        "description": "Anti-forensic memory decoy injector — fills RAM with fake keys, passwords, tokens",
        "service_active": service_active,
        "running": stats.get("running", False),
        "target_mb": stats.get("target_mb", 0),
        "total_decoys": stats.get("total_decoys", 0),
        "total_gb": stats.get("total_gb", 0),
        "mem_usage_mb": stats.get("mem_usage_mb", 0),
        "cycles": stats.get("cycles", 0),
        "blocks_held": stats.get("blocks_held", 0),
        "started_at": stats.get("started_at"),
        "last_cycle": stats.get("last_cycle"),
        "decoy_types": stats.get("decoy_types", {}),
        "academic_basis": [
            "Rutkowska, J. — Beyond the CPU: Defeating Hardware Based RAM Acquisition (Black Hat DC 2007)",
            "Zhang, N. et al. — Memory Forensic Challenges under Misused Architectural Features (Virginia Tech)",
            "Palutke, R. et al. — Hiding Process Memory via Anti-Forensic Techniques (DFRWS 2020)",
            "Weis, S. — Protecting Data In-Use from Firmware and Physical Attacks (Black Hat US 2014)",
            "Srinivasa et al. — Towards systematic honeytoken fingerprinting",
            "US Patent 9774627 — Detecting memory-scraping malware via decoys",
        ],
    }


@router.post("/defense/ram-poison/trigger")
async def ram_poison_trigger() -> dict[str, Any]:
    """Restart RAM Poison service to trigger a fresh injection cycle."""
    try:
        subprocess.run(["systemctl", "restart", "ram-poison.service"], capture_output=True, timeout=10)
        return {"status": "ok", "message": "RAM Poison restarted"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

# ── ME PMT Telemetry — Ring -3 → Ring 0 sensor bridge ────────────────
_PMT_READER = None
_PMT_LOADED = False

def _load_pmt_reader():
    """Import the workspace pmt-reader.py (hyphenated filename → importlib)."""
    global _PMT_READER, _PMT_LOADED
    if _PMT_LOADED:
        return _PMT_READER
    _PMT_LOADED = True
    try:
        import importlib.util as ilu
        path = os.environ.get("PMT_READER", "pmt-reader.py")
        spec = ilu.spec_from_file_location("pmt_reader", path)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _PMT_READER = mod
    except Exception as e:
        logger.warning(f"ME PMT: failed to load pmt-reader.py: {e}")
    return _PMT_READER


@public_router.get("/defense/me-telemetry/status")
async def me_telemetry_status() -> dict[str, Any]:
    """Intel ME/PMC platform telemetry via PMT — below-OS sensors the OS can't fake."""
    pmt = _load_pmt_reader()
    if pmt is None:
        return {"name": "ME PMT Telemetry", "available": False,
                "error": "pmt-reader.py not loadable"}

    try:
        from datetime import datetime as _dt
        regions = pmt.discover()
        decoded = 0
        rails: list[dict[str, Any]] = []
        cpu: dict[str, Any] | None = None
        cores: dict[str, Any] = {}
        for r in regions:
            guid = (r.get("guid") or "").lower()
            schema = pmt.load_schema(guid)
            if not schema or not r.get("data"):
                continue
            decoded += 1
            samples = pmt.decode_region(r["data"], schema)
            by_container: dict[str, list[tuple[str, int]]] = {}
            for s in samples:
                cont, _, nm = s["sample"].partition(".")
                by_container.setdefault(cont, []).append((nm, s["value"]))

            if guid == "0x1a067002":  # DMU normal telemetry
                for cont in ("Container_1", "Container_2", "Container_3", "Container_5"):
                    items = by_container.get(cont, [])
                    pair_idx = 0
                    i = 0
                    while i < len(items):
                        if items[i][0] == "VOLTAGE":
                            v = items[i][1]
                            cur = items[i + 1][1] if i + 1 < len(items) and items[i + 1][0] == "CURRENT" else 0
                            frq = items[i + 2][1] if i + 2 < len(items) and items[i + 2][0] == "FREQ" else 0
                            rails.append({
                                "rail": f"{cont}.{chr(97 + pair_idx)}",
                                "voltage": v, "current": cur, "freq": frq,
                                "raw_power": v * cur,
                            })
                            pair_idx += 1
                            i += 3
                        else:
                            i += 1
                c6 = dict(by_container.get("Container_6", []))
                if c6:
                    cpu = {"vid": c6.get("VID", 0), "amps_max": c6.get("AMPS", 0)}
                c7 = dict(by_container.get("Container_7", []))
                if c7:
                    cores = c7

        return {
            "name": "ME PMT Telemetry",
            "description": "Ring -3 → Ring 0 sensor bridge — ME/PMC platform telemetry harvested below the OS (PMT)",
            "available": True,
            "regions_total": len(regions),
            "regions_decoded": decoded,
            "rails": rails,
            "cpu": cpu,
            "cores": cores,
            "academic_basis": [
                "Intel Platform Monitoring Technology (PMT) — DVSEC/OOB aggregator disclosure",
                "intel/Intel-PMT public XML schemas (Apache 2.0)",
                "Dwyer, S. — Ring -3 threat model (Intel ME/CSME)",
            ],
            "timestamp": _dt.now().isoformat(),
        }
    except Exception as e:
        return {"name": "ME PMT Telemetry", "available": False, "error": str(e)}
