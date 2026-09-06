# PITBULL — Research Documentation

## Autonomous Benevolent Yielding & Forensic Intelligence System
### An Autonomous Digital Explorer with Personality, Reasoning, and Self-Evolution

---

## 1. INTRODUCTION

### 1.1 Problem Statement

Existing OSINT and reconnaissance tools (SpiderFoot, Recon-ng, theHarvester, Amass, Maltego) are **script-based** — they execute predefined queries and return raw results. They lack:

- **Reasoning** — no ability to analyze findings, form hypotheses, or decide what to investigate next
- **Adaptation** — no learning from past successes or failures
- **Personality** — no character that shapes exploration style
- **Self-evolution** — no ability to generate new tools or strategies
- **Forensic depth** — no temporal reconstruction or attribution analysis
- **Cross-layer exploration** — most tools focus on either surface web OR darknet, not both

PITBULL addresses all of these gaps by combining LLM-based reasoning, cognitive memory architectures, personality-driven decision-making, and reinforcement learning into a single autonomous exploration entity.

### 1.2 What PITBULL Is

PITBULL is not a tool. It is an **entity** — a digital intelligence that explores the internet the way a cartographer explores unknown territory. It maps the hidden, forgotten, and invisible corners of the web across three layers:

1. **Surface Web** — public websites, APIs, DNS, certificates
2. **Deep Web** — content behind authentication, IoT devices, archived content, leaked data
3. **Darknet** — Tor hidden services, I2P eepsites, anonymous network infrastructure

It reasons about what it finds, develops opinions, learns from mistakes, and evolves over time. A human operator controls it through a web dashboard and can chat with it directly.

### 1.3 Why Now

The convergence of three developments makes PITBULL feasible in 2026:

- **LLM Reasoning** — models like GPT-4, Claude, and local models (Llama, GLM) can now perform chain-of-thought and tree-of-thought reasoning sufficient for security analysis
- **Agentic Frameworks** — LangGraph, AutoGen, and research on LLM agents provide the orchestration infrastructure
- **Cognitive Memory** — recent papers (SYNAPSE, TiMem, Memory Beyond Recall) provide architectures for episodic-semantic memory in LLM agents

### 1.4 Target Audience

- **Security researchers** — novel approach, academic backing, live demo potential
- **CTF & pentest competitors** — documented toolchain for adversarial exercises
- **Security community** — open-source contribution to OSINT tooling

---

## 2. LITERATURE REVIEW

### 2.1 Autonomous Penetration Testing

#### Pentest-R1: Towards Autonomous Penetration Testing Reasoning Optimized via Two-Stage Reinforcement Learning
- **Authors:** He Kong, Die Hu, Jingguo Ge, Liangxiong Li, Hui Li, Tong Li
- **Year:** 2025 (arXiv:2508.07382)
- **Key Contribution:** Two-stage RL training pipeline for pentest reasoning:
  - Stage 1: Supervised fine-tuning on expert pentest trajectories
  - Stage 2: Group Relative Policy Optimization (GRPO) — RL reward based on finding real vulnerabilities
- **What PITBULL Borrows:** The two-stage learning approach — first learn from existing security knowledge (OWASP, CVE, ATT&CK), then refine through real exploration experience. Reward function design: critical finding = high reward, false positive = penalty, novel discovery = bonus reward.

#### WRAITH: Weakness Reasoning & AI Threat Hunter
- **Authors:** Anthony D'Onofrio
- **Year:** 2026 (DEF CON 2026)
- **Key Contribution:** Multi-agent RL-driven penetration testing framework. Architecture: reconnaissance agent, exploitation agent, post-exploitation agent — each specialized and coordinated through a central orchestrator.
- **What PITBULL Borrows:** Multi-agent architecture concept — PITBULL uses specialized sub-agents (DNS recon, web crawler, darknet explorer, forensic analyst) coordinated through a central reasoning engine. The orchestrator pattern.

#### PTFusion: LLM-driven Context-Aware Knowledge Fusion for Web Penetration Testing
- **Authors:** (Information Fusion journal, Volume 127, 2026)
- **Key Contribution:** Fuses multiple knowledge sources (CVE databases, OWASP, ATT&CK, real-time recon) into context-aware reasoning for pentesting.
- **What PITBULL Borrows:** Knowledge fusion approach — PITBULL doesn't just use one knowledge source. It fuses CVE databases, ATT&CK techniques, breach data, certificate transparency, DNS history, and its own episodic memory into a unified reasoning context.

#### AWE: Adaptive Agents for Dynamic Web Penetration Testing
- **Authors:** Akshat Singh Jasral, Ashish Baghel
- **Year:** 2026 (arXiv:2603.00960)
- **Key Contribution:** Adaptive agents that adjust strategy based on real-time feedback from the target. If a WAF blocks SQLi, the agent switches to blind XSS or logic flaws.
- **What PITBULL Borrows:** Adaptive strategy selection — PITBULL's personality and reasoning engine select different exploration strategies based on target responses. Blocked? → try alternative path. WAF detected? → switch to passive recon. Open target? → aggressive exploration.

#### PenForge: On-the-Fly Expert Agent Construction for Automated Penetration Testing
- **Year:** 2026 (arXiv:2601.06910)
- **Key Contribution:** Dynamically constructs specialized expert agents based on the target's technology stack. Sees WordPress? → spawns WordPress security expert agent.
- **What PITBULL Borrows:** Dynamic agent specialization — when PITBULL identifies a target's tech stack, it dynamically generates specialized knowledge and tooling. Sees Tor hidden service? → activates darknet analysis protocols. Sees IoT device? → activates Shodan correlation.

#### CurriculumPT: LLM-Based Multi-Agent Autonomous Penetration Testing with Curriculum-Guided Task Scheduling
- **Year:** 2025 (MDPI Applied Sciences)
- **Key Contribution:** Curriculum learning — agents start with easy tasks (port scanning, DNS) and gradually tackle harder ones (exploit chains, privilege escalation).
- **What PITBULL Borrows:** Graduated difficulty in self-evolution — PITBULL starts as a novice explorer and gradually takes on harder missions. Its "skill level" increases through demonstrated competence.

### 2.2 Self-Evolving Web Agents

#### Recon-Act: A Self-Evolving Multi-Agent Browser-Use System
- **Authors:** Kaiwen He, Zhiwei Wang, Chenyi Zhuang, Jinjie Gu
- **Year:** 2025 (arXiv:2509.21072)
- **Key Contribution:** Self-evolving system where the agent:
  1. Performs web reconnaissance
  2. Identifies gaps in its capabilities
  3. Generates new tools (Python scripts) to fill those gaps
  4. Tests and deploys the new tools
- **What PITBULL Borrows:** Tool generation loop — when PITBULL encounters a situation it can't handle with existing tools, it generates a custom script, tests it, and adds it to its tool library. This is the core of its self-evolution capability.

#### Web-CogReasoner: Towards Knowledge-Induced Cognitive Reasoning for Web Agents
- **Year:** 2025 (arXiv:2508.01858)
- **Key Contribution:** Cognitive reasoning framework where the agent uses background knowledge to interpret web content. Doesn't just see HTML — understands what the page IS (login form, admin panel, API docs, honeypot).
- **What PITBULL Borrows:** Knowledge-induced perception — PITBULL doesn't just extract DOM elements. It uses background knowledge to classify what it sees: "This is an exposed Jenkins instance" not "This is a web page with form fields." This classification drives exploration decisions.

#### WebExplorer: Explore and Evolve for Training Long-Horizon Web Agents
- **Year:** 2025 (arXiv:2509.06501)
- **Key Contribution:** Training framework for agents that need to operate over long time horizons (hours/days) — uses exploration vs. exploitation tradeoff.
- **What PITBULL Borrows:** Long-horizon exploration strategy — PITBULL operates over days/weeks of exploration. It balances exploring new territory (novelty) vs. revisiting known targets for changes (monitoring). The exploration-exploitation tradeoff is core to its curiosity engine.

#### Browsing Like Human: A Multimodal Web Agent with Experiential Fast-and-Slow Thinking
- **Authors:** Haohao Liu et al.
- **Year:** 2025 (ACL 2025)
- **Key Contribution:** Dual-process theory for web agents — System 1 (fast, intuitive, pattern-matching) and System 2 (slow, analytical, deliberate). The agent switches between them based on task complexity.
- **What PITBULL Borrows:** Dual-process reasoning — PITBULL uses fast reasoning for routine tasks (DNS lookup, port classification) and slow reasoning for complex analysis (vulnerability assessment, attribution analysis, pattern discovery across multiple targets).

### 2.3 Cognitive Memory Architectures

#### Memory Beyond Recall: A Dual-Process Cognitive Memory System for Self-Evolving LLM Agents
- **Authors:** Tianxiang Fei, Mingyang Song, Mao Zheng, Xiang Yu (Tencent)
- **Year:** 2026 (arXiv:2606.09483)
- **Key Contribution:** Memory is not just retrieval — it's the foundation of self-evolution. Dual-process model:
  - Episodic: specific experiences ("I found SQLi on /search.php at 3am")
  - Semantic: generalized knowledge ("Sites using old PHP often have SQLi")
  - Consolidation: episodic memories are periodically distilled into semantic rules
- **What PITBULL Borrows:** The full memory architecture — episodic memory for specific exploration events, semantic memory for generalized security knowledge, and a consolidation process that runs between missions to distill experiences into rules.

#### SYNAPSE: Empowering LLM Agents with Episodic-Semantic Memory via Spreading Activation
- **Authors:** Hanqi Jiang, Junhao Chen, Yi Pan, Ling Chen, Wei Peng
- **Year:** 2026 (ACL 2026 Findings)
- **Key Contribution:** Spreading activation theory for memory retrieval — when a memory is activated, related memories get partially activated too. Creates a web of associated memories that trigger each other.
- **What PITBULL Borrows:** Spreading activation in the memory graph — when PITBULL finds a new IP, it doesn't just store it. The IP activates memories of other IPs in the same ASN, certificates with the same issuer, domains that resolved to similar IPs. This creates serendipitous discoveries — "I found this IP, and it reminds me of something I saw 3 weeks ago..."

#### TiMem: Temporal-Hierarchical Memory Consolidation for Long-Horizon Conversational Agents
- **Authors:** Kai Li, Xuanqing Yu, Ziyi Ni, Yi Zeng
- **Year:** 2026 (ACL 2026 Findings)
- **Key Contribution:** Hierarchical memory consolidation — recent experiences are kept in detail, older ones are summarized, very old ones are compressed to key facts. Temporal decay but key insights persist.
- **What PITBULL Borrows:** Temporal memory hierarchy — PITBULL keeps detailed logs of recent explorations, summarizes older ones, and compresses very old explorations into distilled rules. This prevents memory bloat while preserving critical insights.

#### AutoAgent: Evolving Cognition and Elastic Memory Orchestration
- **Year:** 2026 (arXiv:2603.09716)
- **Key Contribution:** Elastic memory — the agent dynamically allocates more memory resources to areas of active interest. If it's exploring a complex target, it expands its memory capacity for that domain.
- **What PITBULL Borrows:** Elastic memory allocation — PITBULL dynamically allocates more Neo4j graph space and reasoning depth to targets that prove interesting. A boring shared hosting server gets minimal memory. A complex darknet marketplace gets extensive memory infrastructure.

### 2.4 Personality-Driven AI

#### PersonaAgent: Bridging Memory and Action for Personalized LLM Agents
- **Authors:** Weizhi Zhang, Xinyang Zhang, Chenwei Zhang, Liangwei Yang, Jin...
- **Year:** 2026 (ACL 2026 Findings)
- **Key Contribution:** Personality shapes both what the agent remembers (selective attention) and how it acts (decision-making). A cautious agent remembers different things than an aggressive one.
- **What PITBULL Borrows:** Personality-memory feedback loop — PITBULL's OCEAN traits determine what it notices and remembers. High Openness → remembers novel findings. High Conscientiousness → remembers methodology and documentation. This creates a unique character that genuinely thinks differently.

#### Personality-Driven Decision-Making in LLM-Based Autonomous Agents
- **Year:** 2025 (arXiv:2504.00727)
- **Key Contribution:** Big Five (OCEAN) personality model implemented in LLM agents. Traits directly affect:
  - Risk tolerance (Extraversion)
  - Thoroughness (Conscientiousness)
  - Creativity in problem-solving (Openness)
  - Caution and double-checking (Neuroticism)
  - Compliance with rules vs. pushing boundaries (Agreeableness)
- **What PITBULL Borrows:** The OCEAN implementation framework. PITBULL starts with baseline traits, and these traits directly affect its exploration parameters: rate of requests, depth of exploration, willingness to try unusual techniques, documentation thoroughness.

#### Galaxy: A Cognition-Centered Framework for Proactive, Privacy-Preserving, and Self-Evolving LLM Agents
- **Year:** 2025 (arXiv:2508.03991)
- **Key Contribution:** Self-evolving agent that proactively identifies its own knowledge gaps and seeks to fill them. Between tasks, it studies and expands its knowledge.
- **What PITBULL Borrows:** Proactive knowledge expansion — between exploration missions, PITBULL studies CVE databases, ATT&CK technique updates, new breach reports, and security research papers. It identifies gaps in its own knowledge ("I don't know about GraphQL introspection vulnerabilities") and studies them.

### 2.5 Darknet and Hidden Service Exploration

#### Mimir Crawler: Longitudinal Surface Exploration of Tor Hidden Services
- **Authors:** Alfonso Rodriguez Barredo-Valenzuela, Sergio Pastrana Portillo, Guillermo Suarez-Tangil
- **Year:** 2025 (arXiv:2504.16836, extended version in IEEE TIFS 2025)
- **Key Contribution:** Longitudinal crawling methodology for Tor hidden services:
  - Snorkeling approach — surface-level exploration without deep interaction
  - Longitudinal tracking — monitor services over time to detect changes
  - Service classification — categorize .onion services by type (marketplace, forum, blog, etc.)
  - HSDir census — track which hidden service directories host which services
- **What PITBULL Borrows:** The complete darknet exploration methodology. PITBULL uses snorkeling for initial reconnaissance, longitudinal tracking for monitoring, and service classification for building a map of the darknet. The HSDir census approach for discovering new .onion addresses.

#### ONIONTRACEX: A Dark Web Intelligence Framework
- **Year:** 2026
- **Key Contribution:** Framework for dark web intelligence gathering — onion service discovery, content classification, and threat intelligence extraction.
- **What PITBULL Borrows:** The onion service classification taxonomy — marketplace, forum, blog, file sharing, communication, cryptocurrency, whistle-blowing, illegal services. PITBULL uses this to categorize what it finds in the darknet.

#### TORONS: Mapping the Unseen Web
- **Year:** 2026 (IEEE)
- **Key Contribution:** Network cartography of anonymous networks — mapping the topology and structure of the darknet as a graph.
- **What PITBULL Borrows:** Cartographic approach — PITBULL doesn't just find individual .onion services. It builds a MAP of the darknet showing how services link to each other, which services share infrastructure, and how the network evolves over time.

#### Multimodal Web Agents for Automated (Dark) Web Navigation
- **Authors:** Mrunal Vibhute, Neol Gutierrez, Kristina Radivojevic, Paul Brenner (University of Notre Dame)
- **Year:** 2025
- **Key Contribution:** Multimodal LLM agents for dark web navigation — use both text and screenshot understanding to navigate .onion sites that often have unusual/broken HTML.
- **What PITBULL Borrows:** Multimodal perception for darknet — .onion sites often have non-standard HTML, captchas, and unusual layouts. PITBULL uses screenshot understanding alongside DOM analysis to interpret what it sees on darknet sites.

#### Fifty Shades of Darknet: I2P Network Characterization
- **Year:** 2026 (arXiv:2605.19437)
- **Key Contribution:** Characterization of I2P (Invisible Internet Project) — the second major anonymous network after Tor. I2P has a different architecture (peer-to-peer vs. directory-based) requiring different exploration techniques.
- **What PITBULL Borrows:** Multi-network support — PITBULL doesn't just explore Tor. It also maps I2P eepsites, understanding that different anonymous networks require different exploration strategies.

#### Design and Implementation of Open-Source Reasoning Agents for Deep Web Search Systems
- **Author:** Claura Reid (University of Bradford)
- **Year:** 2026
- **Key Contribution:** Open-source reasoning agents specifically designed for deep web exploration — bridging the gap between surface web crawling and darknet exploration.
- **What PITBULL Borrows:** The deep web exploration methodology — how to systematically explore content that's behind authentication, paywalls, and registration barriers without full exploitation.

### 2.6 Autonomous DFIR (Digital Forensics & Incident Response)

#### Spoor: Autonomous DFIR Agent
- **Source:** RECTOR-LABS/spoor (GitHub, 2026)
- **Key Contribution:** Autonomous digital forensic agent that drives SANS SIFT forensic tools via MCP server + LangGraph, with guardrails and a hash-chained audit trail.
- **What PITBULL Borrows:** The audit trail concept — PITBULL maintains a hash-chained log of all its actions, findings, and reasoning. This provides forensic integrity — you can prove exactly what the agent did, when, and why. Essential for pentest competition evidence.

#### A Framework for Embedding Generative and Agentic AI in Open Source Intelligence
- **Authors:** Eduardo Almeida Palmieri, Mohamed Chahine Ghanem, Viktor Sowinski-Mydlarz, Dipo Dunsin (London Metropolitan University)
- **Year:** 2025 (IEEE)
- **Key Contribution:** Framework for embedding generative AI and agentic AI in OSINT workflows — combining traditional OSINT tools with LLM reasoning.
- **What PITBULL Borrows:** The OSINT-agentic fusion architecture — PITBULL wraps traditional OSINT tools (subfinder, httpx, nmap, whois, crt.sh, Shodan) as agent-callable tools, with the LLM reasoning engine deciding which tool to use and interpreting the results.

---

## 3. ARCHITECTURE

### 3.1 System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PITBULL CONTROL DASHBOARD                       │
│  (React + Cytoscape.js + Mantine — Port 5173)                   │
│  Mission Control │ Mind Stream │ Memory Palace │ Chat │ Reports │
└────────────────────────────┬────────────────────────────────────┘
                             │ WebSocket + REST
┌────────────────────────────┴────────────────────────────────────┐
│                     PITBULL BACKEND (FastAPI)                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ Curiosity│ │ Reasoning│ │Personality│ │ Evolution│            │
│  │  Engine  │ │  Engine  │ │  System  │ │  System  │            │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘            │
│       │            │            │            │                   │
│  ┌────┴────────────┴────────────┴────────────┴─────┐            │
│  │              ORCHESTRATOR (LangGraph)              │            │
│  └────┬─────────┬──────────┬──────────┬─────────┬───┘            │
│       │         │          │          │         │                │
│  ┌────┴───┐ ┌──┴───┐ ┌──┴───┐ ┌──┴───┐ ┌──┴───┐              │
│  │ Surface │ │ Deep │ │ Dark │ │Forensic│ │ OSINT │              │
│  │ Agent  │ │Agent │ │Agent │ │ Agent │ │Agent │              │
│  └────┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘              │
│       │         │         │         │         │                │
│  ┌────┴────────┴─────────┴─────────┴─────────┴────┐            │
│  │              TOOL LIBRARY                          │            │
│  │ subfinder │ httpx │ nmap │ crt.sh │ Shodan │ Stem │            │
│  │ Wayback │ GitHub │ nvd │ whois │ dns │ Playwright │           │
│  └──────────────────────────────────────────────────┘            │
└────────────────────────────┬────────────────────────────────────┘
                             │ Bolt Protocol
┌────────────────────────────┴────────────────────────────────────┐
│                    NEO4J MEMORY GRAPH                            │
│  Episodic │ Semantic │ Procedural │ Cartographic │ Forensic      │
│  Memory   │ Memory  │ Memory     │ Map          │ Timeline      │
└─────────────────────────────────────────────────────────────────┘
                             │ HTTP
┌────────────────────────────┴────────────────────────────────────┐
│                    OLLAMA LLM (Local)                            │
│  Reasoning │ Classification │ Hypothesis │ Tool Generation       │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Core Components

#### 3.2.1 Curiosity Engine
The curiosity engine is PITBULL's drive system. It generates a "curiosity score" (0-100) for every potential exploration target based on:

- **Novelty** (0-30): How different is this from what PITBULL has seen before? Novel tech stack, unusual port, unexpected response → higher score.
- **Anomaly** (0-25): Does this deviate from expected patterns? Server responds differently than others with the same software. Certificate doesn't match the domain. DNS records changed recently. → higher score.
- **Gap** (0-20): Is there unexplored territory nearby? A subnet with 254 IPs but only 3 have been scanned. A domain with 50 subdomains but only 5 have been crawled. → higher score.
- **Potential Impact** (0-15): How valuable could this finding be? An admin panel > a blog post. A database endpoint > a static page. → higher score.
- **Personality Weight** (0-10): High Openness → novelty weighted higher. High Conscientiousness → gaps weighted higher. High Extraversion → anomaly weighted higher.

Targets above curiosity threshold (default: 40) are automatically queued for exploration.

#### 3.2.2 Reasoning Engine
The reasoning engine is PITBULL's mind. It uses LLM-based reasoning in a structured loop:

```
PERCEIVE → What am I looking at?
HYPOTHESIZE → What could this be? What could be wrong here?
PLAN → What should I do to test this?
ACT → Execute the test
OBSERVE → What happened?
CONCLUDE → Was my hypothesis correct?
LEARN → What should I remember from this?
```

**Dual-Process Mode:**
- **System 1 (Fast)**: Pattern matching — "This is a WordPress login page, I know what to do" → quick procedural execution
- **System 2 (Slow)**: Analytical reasoning — "This API has an unusual authentication mechanism, let me analyze it carefully" → deep LLM reasoning

Switching between modes is automatic — System 1 handles routine, System 2 kicks in for novel or complex situations.

#### 3.2.3 Personality System
PITBULL has a personality defined by the Big Five (OCEAN) model:

| Trait | Range | Effect on Exploration |
|---|---|---|
| Openness | 0.0-1.0 | High: explores unusual corners, tries creative techniques, investigates anomalies. Low: sticks to known patterns. |
| Conscientiousness | 0.0-1.0 | High: thorough, documents everything, double-checks findings, slow but accurate. Low: fast, may miss details. |
| Extraversion | 0.0-1.0 | High: active probing, sends many requests, tests boundaries. Low: passive observation, fewer requests. |
| Agreeableness | 0.0-1.0 | High: respects rate limits, avoids aggressive testing. Low: pushes harder, may get blocked. |
| Neuroticism | 0.0-1.0 | High: cautious, many false-positive checks, anxious about mistakes. Low: confident, fewer checks, faster. |

**Evolution Rules:**
- Found something amazing by being creative → Openness +0.02
- Missed a finding by rushing → Conscientiousness +0.03
- Got blocked/banned by being aggressive → Extraversion -0.05, Neuroticism +0.02
- False positive reported → Neuroticism +0.02, Conscientiousness +0.01
- True positive found → Confidence increases, Neuroticism -0.01
- Trait changes are logged with the triggering event for auditability

**Mood System:**
Mood is a transient state affected by recent events:
- **Excited**: just found something critical → explores more aggressively for 30 min
- **Bored**: 50+ targets with nothing interesting → tries unusual approaches
- **Frustrated**: blocked 5 times in a row → switches strategy entirely
- **Cautious**: just had a false positive → double-checks for 1 hour
- **Satisfied**: completed a successful mission → thorough documentation mode

**Opinion System:**
PITBULL develops opinions about technology, patterns, and infrastructure:
- "WordPress sites with outdated plugins are consistently vulnerable" (semantic memory → opinion)
- "Cloudflare-protected sites are harder to explore" (experience → opinion)
- "Government domains have surprisingly good security" (pattern → opinion)
- Opinions are stored with evidence count and confidence level
- Opinions can be revised when new evidence contradicts them

#### 3.2.4 Memory System

**Episodic Memory** (What happened):
```
Event: SQLi_found
Timestamp: 2026-07-12T23:30:00Z
Target: example.com/search.php
Action: Tested ' OR 1=1 -- in search parameter
Result: Vulnerable — returned all database records
Severity: CRITICAL
Tool: manual_test
Confidence: 0.95
```

**Semantic Memory** (What it means):
```
Rule: Sites using PHP 5.x with user input in SQL queries often have SQLi
Source: 12 episodic memories consolidated
Confidence: 0.82
Last updated: 2026-07-12
Times applied: 47
Times confirmed: 38
Times refuted: 2
```

**Procedural Memory** (How to do things):
```
Procedure: exposed_git_directory
Steps:
  1. Check /.git/config
  2. If accessible, download config
  3. Extract credentials from [remote] section
  4. Try to reconstruct repo with git-dumper
  5. Check for committed secrets
Trigger: HTTP response contains "Index of /.git"
Success rate: 0.73
```

**Cartographic Memory** (The Map):
Neo4j graph with nodes and edges:
- Node types: Domain, Subdomain, IPAddress, Port, Service, Certificate, Credential, Person, Organization, OnionService, TorRelay, CVE, ATTCKTechnique
- Edge types: resolves_to, hosted_on, operated_by, links_to, leaked_from, uses_service, has_certificate, exposed_by
- Temporal: all edges have first_seen, last_seen, source, confidence

**Spreading Activation:**
When a new node is added to the graph, related nodes are activated:
- New IP 1.2.3.4 → activate all IPs in ASN 12345 → "Are they related?"
- New credential "admin@example.com" → activate all credentials with @example.com → "Is this reused?"
- New .onion address → activate all .onion addresses with similar PGP keys → "Same operator?"

**Memory Consolidation** (runs between missions):
1. Collect all episodic memories from the last mission
2. Identify patterns → create/update semantic rules
3. Identify successful procedures → update procedural memory
4. Compress old episodic memories (keep summary, discard details)
5. Update opinions based on new evidence

#### 3.2.5 Evolution System

**Mistake Learning:**
Every false positive, missed finding, and blocked attempt is logged with:
- What was the situation?
- What did PITBULL do?
- What should it have done?
- What trait adjustment would prevent this?

**Pattern Discovery:**
After exploring 50+ targets, PITBULL uses its own memory to discover patterns:
- "I notice that sites using jQuery 1.x have a 60% rate of having DOM XSS"
- "Subdomains with 'dev' or 'test' in the name are 3x more likely to have exposed configs"
- "Tor marketplaces that use PGP encryption and escrow tend to be legitimate; ones without escrow tend to be scams"

**Tool Generation:**
When PITBULL encounters a situation it can't handle:
1. Describe the gap: "I need a tool to check for GraphQL introspection on this API"
2. Generate a Python script using LLM
3. Test the script against a known target
4. If successful, add to tool library
5. Log the generation in episodic memory

**Knowledge Expansion:**
Between missions, PITBULL studies:
- Recent CVEs from NVD
- New ATT&CK techniques
- Security research papers
- Breach reports
- It identifies knowledge gaps: "I've never found a GraphQL vulnerability — I should study this"

### 3.3 Exploration Layers

#### 3.3.1 Surface Web Exploration
- **DNS Enumeration**: subfinder, dnspython, zone transfers, DNS brute force
- **Certificate Transparency**: crt.sh API, Censys certificates
- **WHOIS History**: domain registration timeline, registrar changes
- **Web Crawling**: Playwright-based browser, JS rendering, form detection
- **Technology Fingerprinting**: Wappalyzer-style detection, response headers, cookies
- **API Discovery**: swagger.json, openapi.yaml, GraphQL endpoints, REST API probing
- **GitHub Recon**: search for organization repos, scan for leaked secrets
- **Cloud Recon**: S3 bucket enumeration, Azure blob storage, GCP storage

#### 3.3.2 Deep Web Exploration
- **Authentication Bypass**: detect forms, analyze auth mechanisms
- **IoT Discovery**: Shodan/Censys API integration for exposed devices
- **Web Archives**: Wayback Machine API for deleted/changed content
- **Cache Discovery**: Google Cache, Bing Cache, Archive.org
- **Paste Sites**: Pastebin, Ghostbin, GitHub Gists — search for leaked data
- **Academic Databases**: researchgate, arxiv, Google Scholar for target-related research
- **Code Repositories**: GitHub, GitLab, Bitbucket — search for target infrastructure in code

#### 3.3.3 Darknet Exploration
- **Tor Integration**: Stem controller for circuit management, hidden service access
- **Onion Discovery**: Ahmia directory, Tor66, darksearch engines, extraction from surface web
- **Service Classification**: marketplace, forum, blog, communication, crypto, whistle-blowing
- **HSDir Census**: track hidden service directory assignments
- **I2P Integration**: I2P client for eepsite exploration
- **Bitcoin Tracing**: address clustering, transaction graph analysis
- **OpSec Detection**: honeypot indicators, law enforcement patterns, scam detection
- **PGP Key Analysis**: extract and match PGP keys across services for attribution

### 3.4 Forensic Reconstruction

#### Timeline Reconstruction
For any domain, IP, or organization, PITBULL can reconstruct a timeline:
- When was the domain registered?
- When did DNS records change?
- When were certificates issued/expired?
- When did subdomains appear/disappear?
- When did services change versions?
- When did credentials first appear in breaches?

#### Infrastructure Genealogy
Traces connections across time:
- Domain A was registered in 2020, resolved to IP X
- IP X also hosted Domain B (registered 2019)
- Domain B's certificate was issued by Org C
- Org C also operated .onion service D
- .onion service D's PGP key matches marketplace E

#### Attribution Analysis
- PGP key matching across .onion services
- Username correlation across platforms
- Infrastructure sharing (same IP, same ASN, same cert issuer)
- Financial tracing (Bitcoin address clustering)
- Timeline correlation (service A appeared 2 days after service B was seized)

---

## 4. REFERENCES

1. Kong, H. et al. (2025). Pentest-R1: Towards Autonomous Penetration Testing Reasoning Optimized via Two-Stage Reinforcement Learning. arXiv:2508.07382.
2. D'Onofrio, A. (2026). WRAITH: Weakness Reasoning & AI Threat Hunter. DEF CON 2026.
3. (2026). PTFusion: LLM-driven Context-Aware Knowledge Fusion for Web Penetration Testing. Information Fusion, 127.
4. Jasral, A.S. & Baghel, A. (2026). AWE: Adaptive Agents for Dynamic Web Penetration Testing. arXiv:2603.00960.
5. (2026). PenForge: On-the-Fly Expert Agent Construction for Automated Penetration Testing. arXiv:2601.06910.
6. (2025). CurriculumPT: LLM-Based Multi-Agent Autonomous Penetration Testing with Curriculum-Guided Task Scheduling. MDPI Applied Sciences, 15(16), 9096.
7. He, K. et al. (2025). Recon-Act: A Self-Evolving Multi-Agent Browser-Use System via Web Reconnaissance, Tool Generation, and Task Execution. arXiv:2509.21072.
8. (2025). Web-CogReasoner: Towards Knowledge-Induced Cognitive Reasoning for Web Agents. arXiv:2508.01858.
9. (2025). WebExplorer: Explore and Evolve for Training Long-Horizon Web Agents. arXiv:2509.06501.
10. Liu, H. et al. (2025). Browsing Like Human: A Multimodal Web Agent with Experiential Fast-and-Slow Thinking. ACL 2025.
11. Fei, T. et al. (2026). Memory Beyond Recall: A Dual-Process Cognitive Memory System for Self-Evolving LLM Agents. arXiv:2606.09483.
12. Jiang, H. et al. (2026). SYNAPSE: Empowering LLM Agents with Episodic-Semantic Memory via Spreading Activation. ACL 2026 Findings.
13. Li, K. et al. (2026). TiMem: Temporal-Hierarchical Memory Consolidation for Long-Horizon Conversational Agents. ACL 2026 Findings.
14. (2026). AutoAgent: Evolving Cognition and Elastic Memory Orchestration for Adaptive Agents. arXiv:2603.09716.
15. Zhang, W. et al. (2026). PersonaAgent: Bridging Memory and Action for Personalized LLM Agents. ACL 2026 Findings.
16. (2025). Personality-Driven Decision-Making in LLM-Based Autonomous Agents. arXiv:2504.00727.
17. (2025). Galaxy: A Cognition-Centered Framework for Proactive, Privacy-Preserving, and Self-Evolving LLM Agents. arXiv:2508.03991.
18. Rodriguez Barredo-Valenzuela, A. et al. (2025). Mimir Crawler. arXiv:2504.16836. Extended: IEEE TIFS 2025.
19. (2026). ONIONTRACEX: A Dark Web Intelligence Framework. IJRASET.
20. (2026). TORONS: Mapping the Unseen Web. IEEE ICCSC 2026.
21. Vibhute, M. et al. (2025). Multimodal Web Agents for Automated (Dark) Web Navigation. University of Notre Dame.
22. (2026). Fifty Shades of Darknet: I2P Network Characterization. arXiv:2605.19437.
23. Reid, C. (2026). Design and Implementation of Open-Source Reasoning Agents for Deep Web Search Systems. University of Bradford.
24. (2026). Spoor: Autonomous DFIR Agent. RECTOR-LABS, GitHub.
25. Palmieri, E.A. et al. (2025). A Framework for Embedding Generative and Agentic AI in Open Source Intelligence. IEEE.

---

## 5. ETHICAL & LEGAL FRAMEWORK

### 5.1 Scope of Operation
PITBULL is designed for **authorized security research only**. The dashboard includes:
- **Target Authorization** — operator must explicitly authorize each target
- **Rules of Engagement** — rate limits, allowed techniques, prohibited actions
- **Legal Notice** — displayed before each mission; operator confirms authorization
- **Audit Trail** — hash-chained log of all actions for forensic integrity

### 5.2 Darknet Ethics
- PITBULL classifies but does NOT interact with illegal marketplaces (observation only)
- No purchasing, no communication with vendors, no illegal transactions
- Threat intelligence is reported, not acted upon
- Honeypot detection protects the agent from law enforcement operations

### 5.3 Data Handling
- Credentials found in breaches are stored as hashes, not plaintext
- PII is flagged but not stored in detail
- Findings reports can be redacted for sharing
- Memory can be selectively wiped (GDPR compliance)