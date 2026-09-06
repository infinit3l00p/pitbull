# PITBULL Phase 8: TOOL TRAP & ADVERSARY CONFUSION ENGINE
## Research Document & Architecture Plan

**Date:** 2026-07-21  
**Author:** Dan Vladoiu  
**Status:** Planning  

---

## VISION

Transform PITBULL from a passive explorer into an **active defender** that:
1. **Traps attacker tools** — captures, analyzes, and saves copies of everything used against the host
2. **Confuses elite adversaries** — Red Team-level deception that wastes their time and breaks their workflow
3. **Learns from every attack** — builds a growing library of attacker TTPs, tools, and malware samples
4. **Optionally discovers novel vulnerabilities** — zero-day discovery via LLM-guided fuzzing (defensive research only)

---

## ACADEMIC RESEARCH

### Deception & Honeypot Technology

| Paper | Year | Source | Key Contribution |
|-------|------|--------|------------------|
| **ADAPT: Adaptive Camouflage Based Deception Orchestration For Trapping APTs** | 2024 | ACM Digital Threats (IIT Kanpur) | Multi-layered deception that adapts based on attacker behavior. Dynamic camouflage that changes the network appearance to match attacker expectations, then traps them. |
| **Deception-in-Depth Using Multiple Layers of Deception** | 2024 | arXiv (Landsborough et al.) | Multiple overlapping deception layers — if one fails, others catch the attacker. Each layer provides independent deception signals. |
| **VelLMes: High-Interaction AI-Based Deception Framework** | 2025 | IEEE EuroS&PW | LLM-powered high-interaction honeypot that generates realistic system responses in real-time. |
| **Cloak, Honey, Trap: Proactive Defenses Against LLM Agents** | 2025 | USENIX Security | Defenses against AI-powered attackers — honeypots designed to trap autonomous LLM hacking agents by poisoning their context. |
| **Honeyquest for LLMs: Rethinking Cyber Deception for AI Attackers** | 2026 | arXiv (Horizon3.ai) | Deception specifically designed to confuse LLM-based attack agents — injects false context into their reasoning chains. |
| **Cisco-Talos DECEIVE** | 2024 | GitHub (286★) | LLM-powered SSH honeypot that simulates entire backend systems. Generates realistic file systems, process lists, and command outputs. |
| **Cyber Deception Reactive: TCP Stealth Redirection to On-Demand Honeypots** | 2024 | arXiv | Stealth TCP redirection — attackers don't know they've been redirected to a honeypot until it's too late. |
| **GAN-Generated Honeypots for Dynamic Cyber Deception (DeepDeceive)** | 2025 | IEEE ICAFT | GANs generate realistic honeypot fingerprints that adapt to evade attacker detection. |
| **Tool-Driven Dynamic Bait Generation in a Lightweight Multimodal Honeypot with Localized LLMs** | 2025 | IEEE CyberC | Dynamic bait generation — LLM creates contextually appropriate fake files, credentials, and services to lure attackers deeper. |
| **ADAPT Patent: System and method for adaptive deception orchestration** | 2025 | US Patent 20250254196A1 | Patented method for adaptive deception that orchestrates multiple deception layers based on real-time attacker profiling. |

### Zero-Day Discovery via LLM

| Paper | Year | Source | Key Contribution |
|-------|------|--------|------------------|
| **VulnLLM-R: Specialized Reasoning LLM for Vulnerability Detection** | 2025 | arXiv | First specialized reasoning LLM for vulnerability detection — uses agent scaffold to analyze code paths. |
| **All You Need Is A Fuzzing Brain** | 2025 | arXiv (DARPA AIxCC finalist) | LLM-powered fuzzing system — DARPA AI Cyber Challenge finalist. Automated vulnerability detection and patching. |
| **LLAMAFUZZ: LLM Enhanced Greybox Fuzzing** | 2024 | arXiv (UC Davis) | LLM guides greybox fuzzer mutation strategies — improves code coverage and crash discovery. |
| **ELFuzz: Efficient Input Generation via LLM-driven Synthesis Over Fuzzer Space** | 2025 | arXiv (OSU) | LLM synthesizes fuzzing strategies rather than just inputs — meta-level fuzzing. |
| **Hybrid Fuzzing with LLM-Guided Input Mutation and Semantic Feedback** | 2025 | arXiv | Combines LLM semantic understanding with traditional fuzzing for deeper code path exploration. |
| **LLM4Fuzz: Guided Fuzzing of Smart Contracts with LLMs** | 2024 | arXiv | LLM-guided fuzzing applied to smart contracts — finds reentrancy and overflow bugs. |
| **Mut4All: Fuzzing Compilers via LLM-Synthesized Mutators Learned from Bug Reports** | 2025 | arXiv | LLM learns mutation strategies from past bug reports — creates targeted fuzzers. |
| **PILOT: Command-line Interface Fuzzing via Path-Guided LLM Prompting** | 2025 | arXiv | LLM-guided CLI fuzzing — follows execution paths to discover input handling bugs. |

### Tool & Malware Capture

| Paper/Project | Year | Source | Key Contribution |
|---------------|------|--------|------------------|
| **Dionaea + DORA** | 2025 | Acta Informatica Pragensia | Real-time malware sample collection from honeypots — Dionaea observation and data analysis. |
| **HoneyWin: High-Interaction Windows Honeypot** | 2025 | arXiv (Singapore) | High-interaction Windows honeypot — captures full attacker session including uploaded tools. |
| **IoTPOT** | 2015-2025 | YNU Japan | IoT honeypot with malware binary dataset — 10+ years of captured samples. |
| **honey-ai** | 2025 | GitHub | All-in-one AI honeypot — SSH, HTTP, FTP, Telnet, MySQL, Redis, Git, VNC, RDP with canary tokens, tarpits, GZIP bombs. |

---

## ASIAN HACKING CONFERENCES (2025-2026)

### Tier 1: Major International (Asia)

| Conference | Date | Location | Focus |
|-----------|------|----------|-------|
| **DEF CON Singapore** | Apr 28-30, 2026 | Marina Bay Sands, Singapore | Full DEF CON experience in Asia — talks, villages, CTF |
| **Black Hat Asia 2026** | 2026 | Marina Bay Sands, Singapore | AI threats, supply chain vulnerabilities, cutting-edge research |
| **HITCON 2026** | Aug 21-22, 2026 | Academia Sinica, Taipei, Taiwan | "When AI Acts" — hacking agentic AI systems |
| **POC 2026** | Nov 12-13, 2026 | Seoul, South Korea | Vulnerability discovery, exploitation, advanced RE training |
| **Codegate 2026** | Jul 23, 2026 | Seoul, South Korea | Human vs AI hacking showdown — CTF + talks |
| **CYBERSEC 2026** | 2026 | Taipei, Taiwan | "Resilient Future" — largest cybersecurity conference in Asia |

### Tier 2: Regional & Specialized (Asia)

| Conference | Date | Location | Focus |
|-----------|------|----------|-------|
| **OFF-BY-ONE 2026** | Sep 14-15, 2026 | Singapore | "By hackers, for hackers" — 3rd edition |
| **OASec 2026** | Sep 28, 2026 | Singapore | AI Safety & Security — Asia Pacific focus |
| **HackTheon Sejong 2026** | 2026 | Sejong, South Korea | Cybersecurity in the era of AI transformation |
| **BCS 2026** | Jun 2026 | Beijing, China | Beijing Cybersecurity Conference — AI security, embodied AI safety |
| **ISC.AI 2026** | Jun 2026 | Beijing, China | 360's AI vulnerability discovery agent "图龙锋" + automated defense "仪天阵" |
| **SciSec 2026** | May 28-30, 2026 | Beijing, China | International Conference on Science of Cyber Security |
| **GeekCon** | 2024+ | China | Hands-on hacking — had CTF challenge to hack BMS and blow up battery remotely |

### Key Themes from Asian Conferences 2025-2026:
1. **AI vs AI** — attackers using LLMs, defenders using LLMs (Codegate, HITCON, BCS)
2. **Autonomous vulnerability discovery** — 360's "图龙锋" at ISC.AI is literally what we're building
3. **Agentic system security** — HITCON's theme "When AI Acts"
4. **Supply chain attacks** — Black Hat Asia focus
5. **Hardware/IoT hacking** — GeekCon's battery explosion CTF

---

## ARCHITECTURE: PITBULL Phase 8

### Module 1: TOOL TRAP ENGINE (TrapCard)
**Purpose:** Capture attacker tools, binaries, scripts, and payloads

```
┌─────────────────────────────────────────────────┐
│              TOOL TRAP ENGINE                    │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Fake SSH │  │ Fake Web │  │ Fake FTP │ ...   │
│  │ Server   │  │ Upload   │  │ Server   │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │              │
│       └──────────────┴──────────────┘            │
│                      │                           │
│              ┌───────▼────────┐                   │
│              │ Tool Capture   │                   │
│              │ - Save binary  │                   │
│              │ - Hash + metadata│                  │
│              │ - Full session │                   │
│              │   recording    │                   │
│              └───────┬────────┘                   │
│                      │                           │
│              ┌───────▼────────┐                   │
│              │ Analysis       │                   │
│              │ - String extract│                  │
│              │ - YARA scan    │                   │
│              │ - Behavior log │                   │
│              │ - ATT&CK map  │                   │
│              └───────┬────────┘                   │
│                      │                           │
│              ┌───────▼────────┐                   │
│              │ /opt/pitbull/  │                   │
│              │ captured_tools/│                   │
│              │   ssh/         │                   │
│              │   web/         │                   │
│              │   ftp/         │                   │
│              │   samples/     │                   │
│              └───────────────┘                   │
└─────────────────────────────────────────────────┘
```

**Services to emulate (high-interaction):**
- **SSH honeypot** — fake shell with LLM-generated realistic system (like DECEIVE)
- **Web upload honeypot** — accept file uploads, save copies, return fake success
- **FTP honeypot** — accept files, store them
- **MySQL/Redis honeypot** — accept queries, log everything
- **Fake credential store** — .env files, AWS keys, SSH keys (canary tokens)

**Tool capture pipeline:**
1. Attacker connects to honeypot service
2. Attacker uploads/exploits/drops tools
3. Tool Trap captures: binary, upload metadata, full session recording
4. Analysis: file hash (SHA256), string extraction, YARA rules, behavior analysis
5. Storage: `/opt/pitbull/captured_tools/{service}/{date}/`
6. Neo4j: store as `:ToolSample` node with all metadata + ATT&CK mapping
7. Sentinel: trigger alert, feed into Labyrinth for deeper deception

### Module 2: COGNITIVE CONFUSION ENGINE (BrainMaze)
**Purpose:** Waste attacker time, break their workflow, cause paranoia

**Already partially built in Labyrinth — extend it:**

```
┌──────────────────────────────────────────────────┐
│           COGNITIVE CONFUSION ENGINE              │
│                                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │ Time Wasters │  │ False Trails │  │ Mind    │ │
│  │ - Fake DBs   │  │ - Fake DNS   │  │ Games   │ │
│  │ - Fake creds │  │ - Fake IPs   │  │ - Pretend│ │
│  │ - Fake files │  │ - Fake users │  │   to be  │ │
│  │ - Fake logs  │  │ - Fake history│  │   hacked │ │
│  └──────┬──────┘  └──────┬───────┘  └────┬────┘ │
│         └────────────────┼────────────────┘      │
│                          │                       │
│                  ┌───────▼────────┐              │
│                  │ Erosion Engine  │              │
│                  │ (existing)      │              │
│                  │ - Fake success  │              │
│                  │ - Dead ends     │              │
│                  │ - False flags   │              │
│                  │ - Confusion     │              │
│                  └───────┬────────┘              │
│                          │                       │
│                  ┌───────▼────────┐              │
│                  │ LLM Persona     │              │
│                  │ - Responds like │              │
│                  │   real admin    │              │
│                  │ - Gives false   │              │
│                  │   info convincingly│           │
│                  │ - Leads attacker│              │
│                  │   in circles    │              │
│                  └────────────────┘              │
└──────────────────────────────────────────────────┘
```

**Confusion techniques:**
1. **Fake success** — attacker thinks exploit worked, but it didn't (existing Labyrinth)
2. **False trails** — fake DNS records pointing to honeypots, fake credentials that lead nowhere
3. **Time wasters** — fake databases with 1000s of entries, fake log files with believable content
4. **Persona play** — LLM plays a confused sysadmin who "helps" the attacker waste time
5. **Mirror reality** — attacker's own tools turned against them (show them their own IP, tools)
6. **Rabbit holes** — fake .env files with canary tokens, fake SSH keys that trigger alerts
7. **Paranoia induction** — fake logs showing "someone else is already here", fake attacker profiles
8. **Cognitive overload** — too many fake services, too many fake credentials, too many dead ends

### Module 3: AUTOMATED VULNERABILITY DISCOVERY (Cerberus)
**Purpose:** Discover novel vulnerabilities in software using LLM-guided fuzzing

**This is the "suggestion" part — optional, defensive research only**

```
┌──────────────────────────────────────────────────┐
│           CERBERUS VULN DISCOVERY                 │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Target    │  │ LLM-Guided│  │ Crash    │        │
│  │ Analyzer  │  │ Fuzzer   │  │ Triage   │        │
│  │ - Binary  │  │ - Input  │  │ - Dedupe │        │
│  │   analysis│  │   mutation│  │ - Severity│       │
│  │ - Protocol│  │ - Path   │  │ - Report  │        │
│  │   parsing │  │   guidance│  │ - Store   │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       └─────────────┴─────────────┘               │
│                     │                             │
│             ┌───────▼────────┐                   │
│             │ Vuln Library    │                   │
│             │ - PoC code      │                   │
│             │ - Affected ver  │                   │
│             │ - Severity      │                   │
│             │ - ATT&CK map   │                   │
│             │ - CWE class    │                   │
│             └────────────────┘                   │
└──────────────────────────────────────────────────┘
```

**Based on academic work:**
- **LLAMAFUZZ** — LLM guides fuzzer mutations based on code coverage feedback
- **VulnLLM-R** — Specialized reasoning LLM for vulnerability detection
- **DARPA AIxCC** — DARPA's AI Cyber Challenge shows LLM fuzzing is viable
- **ELFuzz** — LLM synthesizes fuzzing strategies at meta-level

**What it would do:**
1. Analyze target binary/protocol (reverse engineering, protocol identification)
2. LLM generates test inputs based on understanding of the target
3. Feed inputs to target, monitor for crashes/abnormal behavior
4. LLM analyzes crashes — is this a real bug or just a crash?
5. If real bug: generate PoC, classify (CWE), assess severity, map to ATT&CK
6. Store in Neo4j as `:ZeroDayFinding` node

**Important constraints:**
- Only run against software you own or have permission to test
- All findings stored locally for defensive research
- No auto-exploitation — discovery and reporting only

---

## INTEGRATION WITH EXISTING PITBULL

```
┌─────────────────────────────────────────────────────┐
│                  PITBULL v0.8.0                      │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │ Sentinel │  │ Labyrinth│  │ TRAPCARD │ ← NEW     │
│  │ (detect) │──│ (deceive)│──│ (capture)│           │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       │              │              │                 │
│       └──────────────┴──────────────┘                 │
│                      │                               │
│              ┌───────▼────────┐                       │
│              │  Neo4j Memory  │                       │
│              │  Graph         │                       │
│              └───────┬────────┘                       │
│                      │                               │
│              ┌───────▼────────┐                       │
│              │  BRAINMAZE      │ ← NEW (extends        │
│              │  (confusion)    │    Labyrinth)         │
│              └───────┬────────┘                       │
│                      │                               │
│              ┌───────▼────────┐                       │
│              │  CERBERUS      │ ← NEW (optional,       │
│              │  (zero-day)    │    research only)      │
│              └────────────────┘                       │
└─────────────────────────────────────────────────────┘
```

**Data flow:**
1. Sentinel detects attack → feeds to Labyrinth (existing)
2. Labyrinth engages attacker with deception (existing)
3. **TrapCard** captures any tools the attacker drops (NEW)
4. **BrainMaze** escalates confusion based on attacker behavior (NEW)
5. All data stored in Neo4j: attacker profiles, tool samples, session recordings
6. **Cerberus** can optionally analyze captured tools for new vulnerabilities (NEW)

---

## IMPLEMENTATION PLAN

### Phase 8a: TrapCard (Tool Capture) — 2-3 days
1. Fake SSH server (asyncio + LLM-generated responses)
2. Fake web upload handler (FastAPI endpoint that saves files)
3. File capture pipeline (hash, metadata, storage)
4. Analysis pipeline (strings, YARA, behavior)
5. Neo4j storage (`:ToolSample`, `:AttackerSession`)
6. API endpoints + frontend page

### Phase 8b: BrainMaze (Cognitive Confusion) — 2-3 days
1. Extend Labyrinth erosion engine with new fake success types
2. LLM persona system (fake admin, fake help desk, fake other attacker)
3. False trail generator (fake DNS, fake IPs, fake credentials)
4. Paranoia induction (fake logs, fake session indicators)
5. API endpoints + frontend page

### Phase 8c: Cerberus (Vuln Discovery) — 3-4 days (OPTIONAL)
1. Target analyzer (binary analysis, protocol identification)
2. LLM-guided fuzzer (input mutation, path guidance)
3. Crash triage (dedup, severity, CWE classification)
4. Vuln library (PoC storage, ATT&CK mapping)
5. API endpoints + frontend page

### Phase 8d: Research & Conference Tracking — ongoing
1. Monitor Asian conference proceedings (POC, HITCON, Black Hat Asia, Codegate)
2. Track arXiv papers on deception, fuzzing, and AI security
3. Update knowledge base with new techniques
4. Build a "conference watcher" cron job

---

## DIRECTORY STRUCTURE

```
/opt/pitbull/captured_tools/          # Captured attacker tools
  ├── ssh/                           # From SSH honeypot
  │   ├── 2026-07-21/
  │   │   ├── session_001/
  │   │   │   ├── uploaded_binary    # The actual file
  │   │   │   ├── metadata.json      # Hash, size, type, source IP
  │   │   │   ├── session.log        # Full session recording
  │   │   │   └── analysis.json     # Strings, YARA, ATT&CK
  ├── web/                           # From web honeypot
  ├── ftp/                           # From FTP honeypot
  └── samples/                       # Malware samples (by hash)

/path/to/PITBULL/
  backend/app/
    trapcard/                        # NEW: Tool Trap module
      __init__.py
      ssh_honeypot.py               # Fake SSH server
      web_honeypot.py               # Fake web upload
      ftp_honeypot.py               # Fake FTP
      capture.py                    # File capture pipeline
      analyzer.py                   # Tool analysis
    brainmaze/                       # NEW: Cognitive confusion (extends Labyrinth)
      __init__.py
      persona.py                    # LLM persona system
      false_trails.py               # Fake DNS/IP/creds
      paranoia.py                   # Paranoia induction
      time_wasters.py               # Fake databases, logs
    cerberus/                        # NEW: Vuln discovery (optional)
      __init__.py
      target_analyzer.py
      llm_fuzzer.py
      crash_triage.py
      vuln_library.py
```

---

## ACADEMIC PAPERS TO TRACK

### Deception
- ADAPT (IIT Kanpur, 2024) — adaptive camouflage for APTs
- VelLMes (Czech Technical University, 2025) — AI-based deception
- Cloak Honey Trap (Ben Gurion University, 2025) — trapping LLM attackers
- Honeyquest (Horizon3.ai, 2026) — deception for AI attackers
- Cisco DECEIVE (Talos, 2024) — LLM honeypot

### Zero-Day Discovery
- VulnLLM-R (2025) — specialized reasoning LLM for vuln detection
- LLAMAFUZZ (UC Davis, 2024) — LLM-enhanced greybox fuzzing
- DARPA AIxCC finalists (2025) — automated vuln detection + patching
- ELFuzz (OSU, 2025) — LLM-driven fuzzer synthesis

### Asian Research
- IoTPOT (YNU Japan) — IoT honeypot malware collection
- HoneyWin (Singapore, 2025) — Windows high-interaction honeypot
- 360 ISC.AI "图龙锋" — China's AI vulnerability discovery agent

---

## SECURITY & ETHICS

- **Defensive only** — Pitbull traps and analyzes, never attacks
- **Tool capture** is passive — we save what attackers voluntarily bring to us
- **Vulnerability discovery** (Cerberus) is optional and only runs against software we own
- **No weaponization** — findings are stored for research, not turned into exploits
- **Conference research** is for knowledge — we learn from the community, don't plagiarize
- **Attacker privacy** — we log IPs and TTPs but don't doxx individuals

---

## CONFERENCES TO WATCH (Asia Priority)

### 2026 Calendar (sorted by date)
1. **Codegate 2026** — Jul 23, Seoul — Human vs AI hacking
2. **HITCON 2026** — Aug 21-22, Taipei — "When AI Acts" (agentic AI security)
3. **OFF-BY-ONE 2026** — Sep 14-15, Singapore — By hackers, for hackers
4. **OASec 2026** — Sep 28, Singapore — AI Safety & Security
5. **BCS 2026** — Already happened (Jun), Beijing — AI security
6. **DEF CON Singapore** — Apr 28-30, 2026 — Full DEF CON in Asia
7. **POC 2026** — Nov 12-13, Seoul — Vulnerability discovery + exploitation
8. **Black Hat Asia 2026** — 2026, Singapore — AI threats, supply chain

### Recurring (watch for 2027 dates)
- GeekCon (China) — hands-on hardware/software hacking
- CYBERSEC (Taiwan) — largest Asia cybersecurity conference
- HackTheon (South Korea) — AI + cybersecurity
- SciSec (Beijing) — science of cyber security
- ISC.AI (Beijing) — 360's AI security conference

---

## NEXT STEPS

1. **Start with TrapCard** — the SSH honeypot is highest value (captures real tools)
2. **Extend Labyrinth with BrainMaze** — build on existing deception infrastructure
3. **Conference watcher cron** — auto-fetch new papers/talks from Asian conferences
4. **Cerberus later** — zero-day discovery is ambitious, do it after TrapCard + BrainMaze
5. **Update MEMORY.md** with this plan
6. **Save this document** for reference

---

*"The best trap is one where the prey walks in willingly, thinking they're the hunter."*