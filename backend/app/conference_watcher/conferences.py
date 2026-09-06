"""PITBULL Conference Database — Asian security conferences.

Hardcoded conference data with status tracking and date calculations.
All dates are in 2026.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any

# ── Conference Database ────────────────────────────────────────────

CONFERENCE_DB: list[dict[str, Any]] = [
    # ── Tier 1: Major International ────────────────────────────────
    {
        "id": "defcon-sg-2026",
        "name": "DEF CON Singapore",
        "location": "Marina Bay Sands, Singapore",
        "start_date": "2026-04-28",
        "end_date": "2026-04-30",
        "website": "https://defcon.org/",
        "focus_areas": ["general security", "hardware", "crypto", "AI security"],
        "tier": 1,
        "status": "upcoming",
    },
    {
        "id": "blackhat-asia-2026",
        "name": "Black Hat Asia 2026",
        "location": "Singapore",
        "start_date": "2026-03-25",
        "end_date": "2026-03-28",
        "website": "https://www.blackhat.com/asia-26/",
        "focus_areas": ["AI threats", "supply chain security", "cloud security", "exploit development"],
        "tier": 1,
        "status": "upcoming",
    },
    {
        "id": "hitcon-2026",
        "name": "HITCON 2026",
        "location": "Taipei, Taiwan",
        "start_date": "2026-08-21",
        "end_date": "2026-08-22",
        "website": "https://hitcon.org/2026/",
        "focus_areas": ["agentic AI security", "when AI acts", "CTF", "vulnerability research"],
        "tier": 1,
        "status": "upcoming",
    },
    {
        "id": "poc-2026",
        "name": "POC 2026",
        "location": "Seoul, South Korea",
        "start_date": "2026-11-12",
        "end_date": "2026-11-13",
        "website": "https://powerofcommunity.net/",
        "focus_areas": ["vulnerability discovery", "exploitation", "offensive security"],
        "tier": 1,
        "status": "upcoming",
    },
    {
        "id": "codegate-2026",
        "name": "Codegate 2026",
        "location": "Seoul, South Korea",
        "start_date": "2026-07-23",
        "end_date": "2026-07-24",
        "website": "https://codegate.org/",
        "focus_areas": ["human vs AI hacking", "CTF", "vulnerability research"],
        "tier": 1,
        "status": "upcoming",
    },
    {
        "id": "cybersec-2026",
        "name": "CYBERSEC 2026",
        "location": "Taipei, Taiwan",
        "start_date": "2026-05-13",
        "end_date": "2026-05-15",
        "website": "https://cybersec.ith.org.tw/",
        "focus_areas": ["resilient future", "cyber resilience", "AI security"],
        "tier": 1,
        "status": "upcoming",
    },
    # ── Tier 2: Regional ──────────────────────────────────────────
    {
        "id": "offbyone-2026",
        "name": "OFF-BY-ONE 2026",
        "location": "Singapore",
        "start_date": "2026-09-14",
        "end_date": "2026-09-15",
        "website": "https://offbyone.sg/",
        "focus_areas": ["offensive security", "hardware hacking", "community"],
        "tier": 2,
        "status": "upcoming",
    },
    {
        "id": "oasec-2026",
        "name": "OASec 2026",
        "location": "Singapore",
        "start_date": "2026-09-28",
        "end_date": "2026-09-28",
        "website": "https://oasec.com/",
        "focus_areas": ["AI safety", "AI security", "responsible AI"],
        "tier": 2,
        "status": "upcoming",
    },
    {
        "id": "hacktheon-sejong-2026",
        "name": "HackTheon Sejong 2026",
        "location": "Sejong, South Korea",
        "start_date": "2026-06-19",
        "end_date": "2026-06-20",
        "website": "https://hacktheon.kr/",
        "focus_areas": ["CTF", "offensive security", "government security"],
        "tier": 2,
        "status": "upcoming",
    },
    {
        "id": "bcs-2026",
        "name": "BCS 2026",
        "location": "Beijing, China",
        "start_date": "2026-06-04",
        "end_date": "2026-06-05",
        "website": "https://www.bcs.net.cn/",
        "focus_areas": ["cybersecurity", "AI security", "national security"],
        "tier": 2,
        "status": "upcoming",
    },
    {
        "id": "isc-ai-2026",
        "name": "ISC.AI 2026",
        "location": "Beijing, China",
        "start_date": "2026-07-30",
        "end_date": "2026-08-01",
        "website": "https://isc.360.com/",
        "focus_areas": ["AI security", "digital security", "360 security"],
        "tier": 2,
        "status": "upcoming",
    },
    {
        "id": "scisec-2026",
        "name": "SciSec 2026",
        "location": "Beijing, China",
        "start_date": "2026-05-28",
        "end_date": "2026-05-30",
        "website": "http://scisec.org/",
        "focus_areas": ["science of cyber security", "academic research", "formal methods"],
        "tier": 2,
        "status": "upcoming",
    },
    {
        "id": "geekcon-2026",
        "name": "GeekCon 2026",
        "location": "China (TBD)",
        "start_date": "2026-10-18",
        "end_date": "2026-10-19",
        "website": "https://geekcon.org/",
        "focus_areas": ["hardware hacking", "software hacking", "hands-on exploitation"],
        "tier": 2,
        "status": "upcoming",
    },
]


def _parse_date(s: str) -> date:
    """Parse a YYYY-MM-DD string into a date object."""
    return datetime.strptime(s, "%Y-%m-%d").date()


def _today() -> date:
    """Get today's date in UTC."""
    return datetime.now(timezone.utc).date()


def update_conference_status() -> list[dict[str, Any]]:
    """Update the status of all conferences based on the current date.

    Returns the updated conference list.
    """
    today = _today()
    for conf in CONFERENCE_DB:
        start = _parse_date(conf["start_date"])
        end = _parse_date(conf["end_date"])
        if today < start:
            conf["status"] = "upcoming"
        elif start <= today <= end:
            conf["status"] = "ongoing"
        else:
            conf["status"] = "past"
        # Calculate days until start
        conf["days_until"] = (start - today).days
    return CONFERENCE_DB


def get_all_conferences() -> list[dict[str, Any]]:
    """Return all conferences with updated status."""
    return update_conference_status()


def get_upcoming_conferences(days: int = 30) -> list[dict[str, Any]]:
    """Return conferences happening within the next N days."""
    update_conference_status()
    today = _today()
    result = []
    for conf in CONFERENCE_DB:
        start = _parse_date(conf["start_date"])
        delta = (start - today).days
        if 0 <= delta <= days:
            result.append(conf)
    # Sort by start date
    result.sort(key=lambda c: c["start_date"])
    return result


def get_conference(name: str) -> dict[str, Any] | None:
    """Get a specific conference by name (case-insensitive partial match)."""
    update_conference_status()
    name_lower = name.lower()
    for conf in CONFERENCE_DB:
        if name_lower in conf["name"].lower() or name_lower in conf["id"].lower():
            return conf
    return None