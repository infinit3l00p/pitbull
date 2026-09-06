"""Honeypot and OpSec detection for safe darknet exploration.

Detects honeypots, law enforcement operations, and scam indicators
to protect PITBULL during darknet exploration.

Academic basis:
- Mimir Crawler (IEEE TIFS 2025): honeypot detection in Tor
- ONIONTRACEX (2026): threat intelligence for dark web
- Fifty Shades of Darknet (arXiv:2605.19437): I2P characterization
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


class OpSecDetector:
    """Detects honeypots and operational security threats."""

    # Honeypot indicators — patterns that suggest a service is a honeypot
    HONEYPOT_INDICATORS = {
        "timing_anomaly": "Response times too consistent (automated)",
        "canary_token": "Canary token or tracking pixel detected",
        "overly_helpful": "Service provides suspiciously detailed info to new users",
        "new_service_established": "Service appeared very recently and is already well-indexed",
        "captcha_every_page": "Captcha on every page (data collection)",
        "fake_vendor_profiles": "Vendor profiles have stock photos and perfect English",
        "unnatural_metadata": "HTML metadata contains tracking or analytics scripts",
    }

    # Scam indicators
    SCAM_INDICATORS = {
        "escrow_required_no_review": "Requires escrow but no reviews/history",
        "too_good_pricing": "Prices significantly below market rate",
        "no_pgp_key": "Marketplace/vendor with no PGP key",
        "no_escrow": "Marketplace without escrow (direct payment)",
        "phishing_patterns": "URL mimics known service with typos",
        "advance_fee": "Requests payment before delivery without protections",
    }

    # Known law enforcement seizure patterns
    SEIZURE_INDICATORS = {
        "seizure_banner": "Domain seized by law enforcement",
        "redirect_to_gov": "Redirects to .gov domain",
        "maintenance_mode": "Shows 'maintenance' or 'under investigation' page",
    }

    def analyze(self, fetch_result: dict[str, Any]) -> dict[str, Any]:
        """Analyze a fetched .onion page for OpSec threats."""
        threats: list[dict[str, Any]] = []
        risk_level = "low"
        risk_score = 0

        html = fetch_result.get("body_preview", "")
        title = fetch_result.get("title", "")
        url = fetch_result.get("url", "")
        content = (title + " " + html).lower()

        # ── Honeypot Detection ──────────────────────────────────────

        # Check for analytics/tracking scripts (unusual on real .onion sites)
        if "google-analytics" in content or "googletagmanager" in content:
            threats.append({
                "type": "honeypot",
                "indicator": "analytics_script",
                "description": "Analytics tracking detected — unusual for legitimate .onion sites",
                "severity": "high",
            })
            risk_score += 30

        # Check for tracking pixels
        if "pixel" in content and ("track" in content or "beacon" in content):
            threats.append({
                "type": "honeypot",
                "indicator": "tracking_pixel",
                "description": "Tracking pixel detected",
                "severity": "medium",
            })
            risk_score += 15

        # Check for overly polished content (stock photos, perfect formatting)
        if "shutterstock" in content or "getty" in content or "unsplash" in content:
            threats.append({
                "type": "honeypot",
                "indicator": "stock_photos",
                "description": "Stock photography detected — possible honeypot",
                "severity": "medium",
            })
            risk_score += 15

        # Captcha on every page
        if "captcha" in content and "recaptcha" in content:
            threats.append({
                "type": "honeypot",
                "indicator": "captcha",
                "description": "reCAPTCHA detected — data collection risk",
                "severity": "high",
            })
            risk_score += 25

        # ── Scam Detection ──────────────────────────────────────────

        # No PGP key on marketplace
        if "market" in content or "shop" in content or "vendor" in content:
            if not fetch_result.get("pgp_keys"):
                threats.append({
                    "type": "scam",
                    "indicator": "no_pgp_key",
                    "description": "Marketplace/vendor with no PGP key — high scam risk",
                    "severity": "high",
                })
                risk_score += 25

        # Phishing URL patterns (typosquatting)
        known_services = ["silk", "dream", "wall", "empire", "berlusconi"]
        for svc in known_services:
            if svc in url.lower():
                # Check for typosquatting (extra chars, numbers, etc.)
                if re.search(rf"{svc}[\d_]+", url, re.IGNORECASE):
                    threats.append({
                        "type": "scam",
                        "indicator": "typosquatting",
                        "description": f"URL appears to typosquat {svc} market",
                        "severity": "critical",
                    })
                    risk_score += 40

        # ── Seizure Detection ───────────────────────────────────────

        seizure_keywords = ["seized", "law enforcement", "fbi", "dea", "europol",
                           "homeland security", "department of justice"]
        for kw in seizure_keywords:
            if kw in content:
                threats.append({
                    "type": "seizure",
                    "indicator": "seizure_banner",
                    "description": f"Seizure indicator detected: '{kw}'",
                    "severity": "critical",
                })
                risk_score += 50
                break

        # Government redirect
        if ".gov" in str(fetch_result.get("links", [])):
            threats.append({
                "type": "seizure",
                "indicator": "gov_redirect",
                "description": "Links to .gov domain — possible seized service",
                "severity": "critical",
            })
            risk_score += 40

        # ── General Risk Factors ────────────────────────────────────

        # New service (no history)
        if fetch_result.get("body_size", 0) < 500:
            risk_score += 5  # very small page might be new/sketchy

        # ── Risk Level ──────────────────────────────────────────────

        if risk_score >= 60:
            risk_level = "critical"
        elif risk_score >= 40:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"
        else:
            risk_level = "low"

        recommendation = "safe_to_explore"
        if risk_level == "critical":
            recommendation = "do_not_interact — log only"
        elif risk_level == "high":
            recommendation = "observe_only — no interaction"
        elif risk_level == "medium":
            recommendation = "caution — limited interaction"

        return {
            "url": url,
            "risk_level": risk_level,
            "risk_score": min(100, risk_score),
            "threats": threats,
            "threat_count": len(threats),
            "recommendation": recommendation,
            "analyzed_at": datetime.now().isoformat(),
        }


opsec_detector = OpSecDetector()