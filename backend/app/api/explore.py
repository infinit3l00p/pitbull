"""PITBULL API — explore endpoints (mission control)."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter

from app.collectors.certificate_transparency import certificate_collector
from app.collectors.dns_recon import dns_collector
from app.collectors.web_crawler import web_crawler
from app.core.database import cypher_write, cypher_read
from app.core.reasoning import reasoning_engine
from app.core.curiosity import curiosity_engine
from app.core.evolution import apply_event
from app.core.mood import trigger_mood, set_mood, Mood
from app.core.opinions import opinion_system
from app.core.consolidation import memory_consolidator
from app.core.activation import spreading_activation
from app.core.vuln_analyzer import vuln_analyzer
from app.models import ExploreRequest, ExploreResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["exploration"])

# In-memory mission state (for MVP; will move to DB later)
_missions: dict[str, dict] = {}


@router.post("/start", response_model=ExploreResponse)
async def start_exploration(req: ExploreRequest) -> ExploreResponse:
    """Start a new exploration mission."""
    mission_id = str(uuid.uuid4())[:8]

    _missions[mission_id] = {
        "id": mission_id,
        "target": req.target,
        "scope": req.scope,
        "depth": req.depth,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "discoveries": 0,
        "logs": [],
    }

    # Run exploration in background
    asyncio.create_task(_run_mission(mission_id, req))

    return ExploreResponse(
        exploration_id=mission_id,
        target=req.target,
        status="started",
        message=f"Mission {mission_id} started — exploring {req.target} (scope={req.scope}, depth={req.depth})",
    )


@router.get("/{mission_id}")
async def get_mission(mission_id: str) -> dict[str, Any]:
    """Get mission status and logs."""
    if mission_id not in _missions:
        return {"error": "Mission not found", "id": mission_id}
    return _missions[mission_id]


@router.get("/")
async def list_missions() -> dict[str, Any]:
    """List all missions."""
    return {
        "missions": list(_missions.values()),
        "total": len(_missions),
    }


async def _run_mission(mission_id: str, req: ExploreRequest) -> None:
    """Background mission execution."""
    mission = _missions[mission_id]
    target = req.target

    def log(msg: str):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        mission["logs"].append(entry)
        logger.info(f"[Mission {mission_id}] {msg}")

    try:
        # Step 1: DNS Resolution
        log(f"🧭 Resolving DNS for {target}...")
        ips = await dns_collector.resolve(target)
        if ips:
            log(f"✅ Resolved to {len(ips)} IPs: {', '.join(ips)}")

            for ip in ips:
                cypher_write(
                    "MERGE (d:Domain {hostname: $domain}) "
                    "MERGE (i:IPAddress {ip: $ip}) "
                    "MERGE (d)-[:RESOLVES_TO]->(i) "
                    "SET d.last_seen = datetime(), i.last_seen = datetime()",
                    {"domain": target, "ip": ip},
                )
                mission["discoveries"] += 1

                # Spreading activation from new IP
                try:
                    ip_node = cypher_read(
                        "MATCH (i:IPAddress {ip: $ip}) RETURN id(i) AS id",
                        {"ip": ip},
                    )
                    if ip_node:
                        acts = spreading_activation.activate_from_node(ip_node[0]["id"], "IPAddress", ip)
                        if acts:
                            log(f"🔮 Activation from IP {ip}: {len(acts)} nodes activated")
                except Exception:
                    pass
        else:
            log(f"⚠️ No DNS resolution for {target}")

        # Step 2: Subdomain Enumeration
        log("🔍 Discovering subdomains via crt.sh + DNS brute force...")
        subdomains = await dns_collector.enumerate_subdomains(target)
        log(f"✅ Found {len(subdomains)} subdomains")

        for sub in subdomains:
            subname = sub["subdomain"]
            parent = subname.split(".")[1:]  # rough parent extraction
            parent_domain = ".".join(parent) if len(parent) > 1 else target

            cypher_write(
                "MERGE (d:Domain {hostname: $parent}) "
                "MERGE (s:Subdomain {name: $subname}) "
                "MERGE (d)-[:HAS_SUBDOMAIN]->(s) "
                "SET s.last_seen = datetime(), d.last_seen = datetime()",
                {"parent": parent_domain, "subname": subname},
            )
            mission["discoveries"] += 1

            for ip in sub.get("ips", []):
                cypher_write(
                    "MERGE (s:Subdomain {name: $subname}) "
                    "MERGE (i:IPAddress {ip: $ip}) "
                    "MERGE (s)-[:RESOLVES_TO]->(i) "
                    "SET s.last_seen = datetime(), i.last_seen = datetime()",
                    {"subname": subname, "ip": ip},
                )
                mission["discoveries"] += 1

        # Step 3: Certificate Transparency
        log("📜 Querying Certificate Transparency logs...")
        certs = await certificate_collector.get_certificates(target)
        log(f"✅ Found {len(certs)} certificates")

        for cert in certs[:50]:  # limit to 50 certs
            cert_id = cert.get("id", "")
            if cert_id:
                cypher_write(
                    "MERGE (d:Domain {hostname: $domain}) "
                    "MERGE (c:Certificate {id: $cert_id}) "
                    "SET c.issuer = $issuer, c.common_name = $cn, "
                    "c.not_before = $nb, c.not_after = $na, c.serial_number = $sn "
                    "MERGE (d)-[:HAS_CERTIFICATE]->(c) "
                    "SET d.last_seen = datetime()",
                    {
                        "domain": target,
                        "cert_id": cert_id,
                        "issuer": cert.get("issuer_name", ""),
                        "cn": cert.get("common_name", ""),
                        "nb": cert.get("not_before", ""),
                        "na": cert.get("not_after", ""),
                        "sn": cert.get("serial_number", ""),
                    },
                )
                mission["discoveries"] += 1

        # Step 4: Web Crawl (if scope includes surface)
        crawl_result = {"pages_crawled": 0, "pages": []}
        if req.scope in ("surface", "full"):
            url = f"https://{target}" if not target.startswith("http") else target
            log(f"🕷️ Crawling {url} (depth={req.depth})...")
            crawl_result = await web_crawler.crawl(url, max_depth=req.depth)
            log(f"✅ Crawled {crawl_result['pages_crawled']} pages")

            for page in crawl_result.get("pages", []):
                # Store page as memory
                page_url = page.get("url", "")
                if page_url:
                    tech = ", ".join(page.get("tech_hints", []))
                    interesting = ", ".join(page.get("interesting_paths", []))

                    cypher_write(
                        "MERGE (m:Memory {id: $mid}) "
                        "SET m.memory_type = 'episodic', m.content = $content, "
                        "m.target = $url, m.severity = 'info', m.timestamp = datetime()",
                        {
                            "mid": str(uuid.uuid4())[:12],
                            "content": f"Crawled {page_url} (status={page.get('status_code')}, tech={tech}, interesting_paths={interesting})",
                            "url": page_url,
                        },
                    )
                    mission["discoveries"] += 1

        # Step 4b: Deep Web Probing (if scope includes deep or full)
        if req.scope in ("deep", "full", "surface"):
            from app.collectors.deepweb import deep_web_collector
            log("🔬 Probing for hidden endpoints (admin, API, configs)...")
            try:
                deep_results = await deep_web_collector.probe(target)
                found = deep_results.get("found", 0)
                log(f"✅ Deep probe: {found} interesting paths found")

                for result in deep_results.get("results", []):
                    cypher_write(
                        "MERGE (m:Memory {id: $id}) "
                        "SET m.memory_type = 'episodic', m.content = $content, "
                        "m.target = $url, m.severity = $severity, m.timestamp = datetime()",
                        {
                            "id": str(uuid.uuid4())[:12],
                            "content": f"Deep probe: [{result['type']}] {result['url']} (status={result['status']}, {result.get('interesting', '')})",
                            "url": result["url"],
                            "severity": "high" if result["type"] in ("exposed_config", "exposed_git", "backup_file", "debug_endpoint") else "medium" if result["type"] in ("admin_panel", "api_documentation", "graphql_endpoint") else "info",
                        },
                    )
                    mission["discoveries"] += 1

                # Trigger evolution: found something interesting
                if found > 0:
                    trigger_mood("novel_discovery", f"Deep probe found {found} endpoints on {target}")
                    apply_event("true_positive", target, f"Deep probe discovered {found} endpoints")
            except Exception as e:
                log(f"⚠️ Deep probe failed: {e}")

        # Step 4b2: Vulnerability Analysis
        log("🛡️ Analyzing findings for vulnerabilities...")
        try:
            deep_results_list = deep_results.get("results", []) if 'deep_results' in dir() else []
            vuln_findings = vuln_analyzer.analyze_mission(
                target=target,
                crawl_pages=crawl_result.get("pages", []),
                deep_probe_results=deep_results_list,
            )
            if vuln_findings:
                stored = vuln_analyzer.store_findings(vuln_findings)
                log(f"🚨 Classified {stored} vulnerability findings:")
                for vf in vuln_findings:
                    log(f"   ⚠ [{vf['severity'].upper()}] {vf['vuln_class']} — {vf['description'][:80]}")
                # Trigger mood: found vulnerabilities
                trigger_mood("critical_finding", f"{len(vuln_findings)} vulnerabilities classified for {target}")
                apply_event("critical_finding_creative", target, f"{len(vuln_findings)} vulnerabilities found")
            else:
                log("✅ No vulnerabilities classified from passive recon")
        except Exception as e:
            log(f"⚠️ Vulnerability analysis failed: {e}")

        # Step 4c: WHOIS Lookup
        if req.scope in ("deep", "full", "surface"):
            from app.collectors.whois import whois_collector
            log("📋 WHOIS lookup...")
            try:
                whois_data = await whois_collector.lookup(target)
                if whois_data.get("found"):
                    log(f"✅ WHOIS: registered {whois_data.get('creation_date', '?')}, expires {whois_data.get('expiration_date', '?')}")
                    cypher_write(
                        "MERGE (d:Domain {hostname: $domain}) "
                        "SET d.registrar = $registrar, d.creation_date = $creation, "
                        "d.expiry_date = $expiry, d.registrant_org = $org, "
                        "d.registrant_country = $country, d.last_seen = datetime()",
                        {
                            "domain": target,
                            "registrar": whois_data.get("registrar", ""),
                            "creation": whois_data.get("creation_date", ""),
                            "expiry": whois_data.get("expiration_date", ""),
                            "org": whois_data.get("org", ""),
                            "country": whois_data.get("country", ""),
                        },
                    )
                    mission["discoveries"] += 1
            except Exception as e:
                log(f"⚠️ WHOIS failed: {e}")

        # Step 4d: Wayback Machine (if scope includes deep or full)
        if req.scope in ("deep", "full"):
            from app.collectors.wayback import wayback_collector
            log("📚 Querying Wayback Machine...")
            try:
                wayback = await wayback_collector.get_snapshots(target, limit=50)
                snap_count = wayback.get("count", 0)
                log(f"✅ Wayback: {snap_count} historical snapshots found")
                if snap_count > 0:
                    cypher_write(
                        "MERGE (m:Memory {id: $id}) "
                        "SET m.memory_type = 'episodic', m.content = $content, "
                        "m.target = $target, m.severity = 'info', m.timestamp = datetime()",
                        {
                            "id": str(uuid.uuid4())[:12],
                            "content": f"Wayback Machine: {snap_count} snapshots for {target}, first: {wayback.get('first_snapshot', {}).get('datetime', '?')}, last: {wayback.get('last_snapshot', {}).get('datetime', '?')}",
                            "target": target,
                        },
                    )
                    mission["discoveries"] += 1
            except Exception as e:
                log(f"⚠️ Wayback query failed: {e}")

        # Step 4e: GitHub Recon (if scope includes deep or full)
        if req.scope in ("deep", "full"):
            from app.collectors.github import github_collector
            log("🐙 GitHub recon...")
            try:
                secrets = await github_collector.search_secrets(target)
                if secrets.get("count", 0) > 0:
                    log(f"🚨 GitHub: {secrets['count']} potential leaked secrets found!")
                    for s in secrets.get("potential_secrets", [])[:5]:
                        cypher_write(
                            "MERGE (m:Memory {id: $id}) "
                            "SET m.memory_type = 'episodic', m.content = $content, "
                            "m.target = $target, m.severity = 'critical', m.timestamp = datetime()",
                            {
                                "id": str(uuid.uuid4())[:12],
                                "content": f"GitHub potential secret: {s.get('file', '')} in {s.get('repo', '')} — {s.get('html_url', '')}",
                                "target": target,
                            },
                        )
                        mission["discoveries"] += 1
                    trigger_mood("critical_finding", f"GitHub secrets found for {target}")
                    apply_event("critical_finding_creative", target, "GitHub leaked secrets discovered")
                else:
                    log("✅ GitHub: no leaked secrets found")

                infra = await github_collector.search_infrastructure(target)
                if infra.get("count", 0) > 0:
                    log(f"🔧 GitHub: {infra['count']} infrastructure references found")
            except Exception as e:
                log(f"⚠️ GitHub recon failed: {e}")

        # Step 4f: Shodan (if scope includes deep or full and IPs found)
        if req.scope in ("deep", "full") and ips:
            from app.collectors.shodan import shodan_collector
            log("📡 Shodan IP lookup...")
            try:
                shodan_results = await shodan_collector.lookup_ips(ips[:3])
                for result in shodan_results:
                    if result.get("found"):
                        log(f"✅ Shodan: {result['ip']} — {len(result.get('ports', []))} ports, {result.get('org', '')}")
                        cypher_write(
                            "MERGE (i:IPAddress {ip: $ip}) "
                            "SET i.asn = $asn, i.org = $org, i.isp = $isp, "
                            "i.country = $country, i.os = $os, i.last_seen = datetime()",
                        {
                            "ip": result["ip"],
                            "asn": result.get("asn", ""),
                            "org": result.get("org", ""),
                            "isp": result.get("isp", ""),
                            "country": result.get("country", ""),
                            "os": result.get("os", ""),
                        })
                        mission["discoveries"] += 1
                    elif result.get("error") == "no_api_key":
                        log("⚠️ Shodan: no API key set (PITBULL_SHODAN_API_KEY)")
                        break
                    elif result.get("error") == "rate_limited":
                        log("⚠️ Shodan: rate limited")
                        break
            except Exception as e:
                log(f"⚠️ Shodan lookup failed: {e}")

        # Step 4g: Darknet Exploration (if scope includes darknet or full)
        if req.scope in ("darknet", "full"):
            from app.collectors.tor import tor_controller
            from app.collectors.onion import onion_collector
            from app.collectors.opsec import opsec_detector

            if not tor_controller.is_running():
                log("⚠️ Tor not running — start Tor to explore .onion services")
            else:
                log("🔮 Tor is running — beginning darknet exploration")

                # Discover .onion services related to target
                try:
                    log("🔍 Discovering .onion services from directories...")
                    onions = await onion_collector.discover_from_ahmia(query=target)
                    log(f"✅ Found {len(onions)} .onion addresses")

                    for onion_addr in onions[:5]:  # limit to 5 for safety
                        onion_url = f"http://{onion_addr}"
                        log(f"🔮 Classifying {onion_addr}...")

                        result = await onion_collector.classify_onion(onion_url)

                        if result.get("online"):
                            service_type = result.get("service_type", "unknown")
                            title = result.get("title", "")[:50]
                            log(f"  ✅ Online: [{service_type}] {title}")

                            # OpSec analysis
                            opsec = opsec_detector.analyze(result)
                            risk = opsec.get("risk_level", "low")
                            if risk in ("high", "critical"):
                                log(f"  ⚠️ OpSec risk: {risk} — {opsec.get('recommendation', '')}")
                                if risk == "critical":
                                    log(f"  🚨 Skipping {onion_addr} — critical OpSec risk")
                                    continue

                            # Store in Neo4j
                            cypher_write(
                                "MERGE (o:OnionService {address: $addr}) "
                                "SET o.title = $title, o.service_type = $type, "
                                "o.online = true, o.last_checked = datetime(), "
                                "o.classified = $classified, o.risk_level = $risk, "
                                "o.language = $lang",
                                {
                                    "addr": onion_addr,
                                    "title": title,
                                    "type": service_type,
                                    "classified": result.get("classified", False),
                                    "risk": risk,
                                    "lang": result.get("language", "en"),
                                },
                            )
                            mission["discoveries"] += 1

                            # Store episodic memory
                            cypher_write(
                                "MERGE (m:Memory {id: $id}) "
                                "SET m.memory_type = 'episodic', m.content = $content, "
                                "m.target = $target, m.severity = $severity, m.timestamp = datetime()",
                                {
                                    "id": str(uuid.uuid4())[:12],
                                    "content": f"Darknet: classified [{service_type}] {onion_addr} — title: {title}, risk: {risk}",
                                    "target": onion_addr,
                                    "severity": "high" if risk in ("high", "critical") else "medium" if service_type != "unknown" else "info",
                                },
                            )
                            mission["discoveries"] += 1
                        else:
                            err = result.get("error", "offline")
                            log(f"  ❌ {onion_addr}: {err}")

                        await asyncio.sleep(2.0)  # rate limit for .onion

                except Exception as e:
                    log(f"⚠️ Darknet exploration failed: {e}")

                # Relay census
                try:
                    from app.collectors.relay import relay_census
                    log("📡 Collecting Tor relay census...")
                    census = await relay_census.get_relays(limit=50)
                    if "error" not in census:
                        relay_count = census.get("count", 0)
                        log(f"✅ Relay census: {relay_count} relays mapped")
                        if relay_count > 0:
                            analysis = relay_census.analyze_census(census.get("relays", []))
                            cypher_write(
                                "MERGE (m:Memory {id: $id}) "
                                "SET m.memory_type = 'cartographic', m.content = $content, "
                                "m.target = 'tor_network', m.severity = 'info', m.timestamp = datetime()",
                                {
                                    "id": str(uuid.uuid4())[:12],
                                    "content": f"Tor relay census: {analysis['total_relays']} relays, {len(analysis['countries'])} countries, top: {list(analysis['countries'].items())[:3]}",
                                },
                            )
                            mission["discoveries"] += 1
                except Exception as e:
                    log(f"⚠️ Relay census failed: {e}")

                # I2P status check
                try:
                    from app.collectors.i2p import i2p_collector
                    i2p_status = i2p_collector.get_status()
                    if i2p_status.get("running"):
                        log("✅ I2P router detected — eepsite exploration available")
                    else:
                        log("ℹ️ I2P router not running — install I2P for eepsite exploration")
                except Exception as e:
                    log(f"⚠️ I2P status check failed: {e}")
        log("🧠 PITBULL is reasoning about findings...")
        try:
            summary = f"Explored {target}: {len(subdomains)} subdomains, {len(certs)} certificates, {crawl_result.get('pages_crawled', 0)} pages crawled. Technologies found: {set().union(*[p.get('tech_hints', []) for p in crawl_result.get('pages', [])])}"
            reasoning = reasoning_engine.think(
                observation=summary,
                context=f"Target: {target}, Scope: {req.scope}",
            )
            log(f"💭 PITBULL thinks: {reasoning.get('thought', '...')[:200]}")
            log(f"🎯 Recommended action: {reasoning.get('action', '...')[:200]}")
        except Exception as e:
            log(f"⚠️ Reasoning failed: {e}")

        mission["status"] = "completed"
        log(f"✅ Mission complete — {mission['discoveries']} discoveries")

        # ── Phase 2: Post-mission intelligence ────────────────────

        # Trigger mood: mission success
        trigger_mood("mission_success", f"Completed exploration of {target}")
        apply_event("mission_success", target, f"Mission {mission_id} completed with {mission['discoveries']} discoveries")

        # Form opinions from findings
        try:
            log("🧠 Forming opinions from findings...")
            all_findings = []
            for page in crawl_result.get("pages", []):
                all_findings.append({
                    "tech_hints": page.get("tech_hints", []),
                    "interesting_paths": page.get("interesting_paths", []),
                    "url": page.get("url", ""),
                })
            opinion_result = opinion_system.generate_opinion_from_findings(target, all_findings)
            if opinion_result:
                for op in opinion_result.get("opinions_formed", []):
                    log(f"💭 Opinion formed: {op.get('subject', '')} (conf={op.get('confidence', 0):.2f})")
        except Exception as e:
            log(f"⚠️ Opinion formation failed: {e}")

        # Run memory consolidation
        try:
            log("📚 Consolidating memories...")
            consolidation = memory_consolidator.consolidate(since_hours=24)
            if consolidation["patterns_found"]:
                log(f"📚 Found {consolidation['patterns_found']} patterns → {consolidation['semantic_rules_created']} new rules, {consolidation['semantic_rules_updated']} updated")
        except Exception as e:
            log(f"⚠️ Memory consolidation failed: {e}")

        # Update mission stats in personality state
        try:
            from app.api.personality import _load_state, _save_state
            state = _load_state()
            state.missions_completed += 1
            state.findings_total += mission["discoveries"]
            _save_state(state)
        except Exception:
            pass

        log("🧠 Intelligence processing complete")

        # ── Phase 5: Evolution ──────────────────────────────────────

        # Run pattern discovery (if enough data)
        try:
            from app.core.patterns import pattern_discovery
            log("🔍 Discovering patterns from exploration history...")
            patterns = pattern_discovery.discover_patterns(min_targets=3)
            if patterns.get("patterns_found", 0) > 0:
                log(f"🔍 Found {patterns['patterns_found']} patterns, {len(patterns.get('insights', []))} insights")
                for insight in patterns.get("insights", [])[:3]:
                    log(f"💡 Insight: {insight.get('insight', '')[:100]}")
        except Exception as e:
            log(f"⚠️ Pattern discovery failed: {e}")

        # Apply personality drift
        try:
            from app.core.drift import personality_drift
            log("🔄 Applying personality drift...")
            drift = personality_drift.calculate_drift(days=7)
            if drift.get("drift_count", 0) > 0:
                log(f"🔄 Personality drifted: {drift['drift_count']} trait adjustments")
        except Exception as e:
            log(f"⚠️ Personality drift failed: {e}")

        # Check for tool generation gaps
        try:
            from app.core.tool_gen import tool_generator
            existing_tools = [t.get("name", "") for t in tool_generator.get_tools()]
            all_findings_for_gap = []
            for page in crawl_result.get("pages", []):
                all_findings_for_gap.append({"content": str(page), "url": page.get("url", ""), "target": target})
            gap = tool_generator.identify_gap(all_findings_for_gap, existing_tools)
            if gap:
                log(f"🔧 Capability gap detected: {gap}")
                # Actually generate the tool to fill the gap
                try:
                    gen_result = await tool_generator.generate_tool(
                        gap=gap,
                        context=str(all_findings_for_gap[:3])[:500],
                        target=target,
                    )
                    if gen_result.get("generated"):
                        log(f"🔧 Tool generated: {gen_result.get('name', 'unknown')} → {gen_result.get('path', '')}")
                    elif gen_result.get("error"):
                        log(f"⚠️ Tool generation failed: {gen_result['error']}")
                except Exception as gen_err:
                    log(f"⚠️ Tool generation error: {gen_err}")
        except Exception as e:
            log(f"⚠️ Tool gap check failed: {e}")

    except Exception as e:
        mission["status"] = "failed"
        log(f"❌ Mission failed: {e}")
        logger.exception(f"Mission {mission_id} failed")

        # Trigger mood: mission failed
        trigger_mood("mission_failed", f"Mission {mission_id} failed: {e}")
        apply_event("mission_failed", target, str(e))