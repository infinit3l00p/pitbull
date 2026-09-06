// PITBULL API client
const API_KEY = localStorage.getItem("pitbull_api_key") || "pitbull-explorer-dev-key-2026";
const BASE = "/api/v1";

export function setApiKey(key: string) {
  localStorage.setItem("pitbull_api_key", key);
}

function headers() {
  return { "X-API-Key": API_KEY, "Content-Type": "application/json" };
}

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
  neo4j: { connected: boolean };
}

export interface ExploreRequest {
  target: string;
  depth?: number;
  scope?: string;
  rate_limit_ms?: number;
}

export interface ExploreResponse {
  exploration_id: string;
  target: string;
  status: string;
  discoveries: number;
  message: string;
}

export interface Mission {
  id: string;
  target: string;
  scope: string;
  depth: number;
  status: string;
  started_at: string;
  discoveries: number;
  logs: string[];
}

export interface GraphData {
  nodes: { id: number; type: string; label: string; props: Record<string, string> }[];
  edges: { source: number; target: number; type: string }[];
}

export interface GraphStats {
  domain: number;
  subdomain: number;
  ipaddress: number;
  certificate: number;
  memory: number;
  onionservice: number;
  cve: number;
  total_edges: number;
}

export interface PersonalityState {
  openness: number;
  conscientiousness: number;
  extraversion: number;
  agreeableness: number;
  neuroticism: number;
  mood: string;
  mood_expires: string | null;
  opinions: Record<string, unknown>[];
  missions_completed: number;
  findings_total: number;
  false_positives: number;
  mistakes_learned: number;
}

export interface MoodState {
  mood: string;
  expires: string | null;
  effects: Record<string, number>;
}

export interface Opinion {
  id: string;
  subject: string;
  text: string;
  confidence: number;
  evidence_count: number;
  supporting_count: number;
  contradictions: number;
  category: string;
  revised: boolean;
  first_formed: string;
  last_updated: string;
}

export interface SemanticRule {
  id: string;
  subject: string;
  content: string;
  rule_type: string;
  confidence: number;
  evidence_count: number;
  times_applied: number;
  times_confirmed: number;
  times_refuted: number;
  last_updated: string;
}

export interface CuriosityTarget {
  target: string;
  total: number;
  novelty: number;
  anomaly: number;
  gap: number;
  impact: number;
  personality_weight: number;
  reason: string;
  priority: string;
  timestamp: string;
}

export interface EvolutionEntry {
  trait: string;
  delta: number;
  reason: string;
  event_type: string;
  target: string;
  timestamp: string;
}

export interface Memory {
  id: string;
  type: string;
  content: string;
  target: string;
  severity: string;
  timestamp: string;
}

export const api = {
  // Generic get helper
  async get(url: string): Promise<any> {
    const r = await fetch(`${BASE}${url}`, { headers: headers() });
    if (!r.ok) throw new Error(`API ${r.status}: ${url}`);
    return r.json();
  },
  // Generic post helper for antiforensics and other endpoints
  async post(url: string, body?: any): Promise<any> {
    const r = await fetch(`${BASE}${url}`, {
      method: "POST",
      headers: headers(),
      body: body ? JSON.stringify(body) : undefined,
    });
    return r.json();
  },

  async health(): Promise<HealthResponse> {
    const r = await fetch("/health");
    return r.json();
  },

  async startExploration(req: ExploreRequest): Promise<ExploreResponse> {
    const r = await fetch(`${BASE}/explore/start`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(req),
    });
    return r.json();
  },

  async getMission(id: string): Promise<Mission> {
    const r = await fetch(`${BASE}/explore/${id}`, { headers: headers() });
    return r.json();
  },

  async listMissions(): Promise<{ missions: Mission[]; total: number }> {
    const r = await fetch(`${BASE}/explore/`, { headers: headers() });
    return r.json();
  },

  async getFullGraph(limit = 500): Promise<GraphData> {
    const r = await fetch(`${BASE}/graph/full?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  async getGraphStats(): Promise<GraphStats> {
    const r = await fetch(`${BASE}/graph/stats`, { headers: headers() });
    return r.json();
  },

  async getMemories(limit = 50, type?: string): Promise<{ memories: Memory[]; count: number }> {
    const url = type
      ? `${BASE}/graph/memories?limit=${limit}&memory_type=${type}`
      : `${BASE}/graph/memories?limit=${limit}`;
    const r = await fetch(url, { headers: headers() });
    return r.json();
  },

  async getPersonality(): Promise<PersonalityState> {
    const r = await fetch(`${BASE}/personality/`, { headers: headers() });
    return r.json();
  },

  async clearGraph(): Promise<{ status: string }> {
    const r = await fetch(`${BASE}/graph/clear?confirm=DELETE_EVERYTHING`, { method: "DELETE", headers: headers() });
    return r.json();
  },

  // ── Phase 2: Intelligence ────────────────────────────────────────

  async getMood(): Promise<MoodState> {
    const r = await fetch(`${BASE}/mood`, { headers: headers() });
    return r.json();
  },

  async getOpinions(category?: string): Promise<{ opinions: Opinion[]; count: number }> {
    const url = category ? `${BASE}/opinions?category=${category}` : `${BASE}/opinions`;
    const r = await fetch(url, { headers: headers() });
    return r.json();
  },

  async getSemanticRules(limit = 50): Promise<{ rules: SemanticRule[]; count: number }> {
    const r = await fetch(`${BASE}/memory/semantic?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  async getCuriosityQueue(limit = 20): Promise<{ queue: CuriosityTarget[]; count: number }> {
    const r = await fetch(`${BASE}/curiosity/queue?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  async getEvolutionHistory(limit = 50): Promise<{
    history: EvolutionEntry[];
    summary: {
      total_adjustments: number;
      trait_deltas: Record<string, number>;
      event_counts: Record<string, number>;
      history: EvolutionEntry[];
    };
  }> {
    const r = await fetch(`${BASE}/personality/evolution?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  // ── Phase 3: Deep Exploration ────────────────────────────────────

  async getWHOIS(domain: string): Promise<any> {
    const r = await fetch(`${BASE}/whois/${domain}`, { headers: headers() });
    return r.json();
  },

  async getWaybackSnapshots(domain: string, limit = 100): Promise<any> {
    const r = await fetch(`${BASE}/wayback/snapshots/${domain}?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  async getGitHubSecrets(domain: string): Promise<any> {
    const r = await fetch(`${BASE}/github/secrets/${domain}`, { headers: headers() });
    return r.json();
  },

  async getForensicTimeline(target: string): Promise<any> {
    const r = await fetch(`${BASE}/forensic/timeline/${target}`, { headers: headers() });
    return r.json();
  },

  async getInfrastructureGenealogy(target: string): Promise<any> {
    const r = await fetch(`${BASE}/forensic/genealogy/${target}`, { headers: headers() });
    return r.json();
  },

  // ── Phase 4: Darknet ────────────────────────────────────────────

  async getTorStatus(): Promise<any> {
    const r = await fetch(`${BASE}/tor/status`, { headers: headers() });
    return r.json();
  },

  // ── Phase 5: Evolution ────────────────────────────────────────────

  async getMistakes(limit = 50): Promise<any> {
    const r = await fetch(`${BASE}/mistakes?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  async getMistakeStats(): Promise<any> {
    const r = await fetch(`${BASE}/mistakes/stats`, { headers: headers() });
    return r.json();
  },

  async getLessons(): Promise<any> {
    const r = await fetch(`${BASE}/mistakes/lessons`, { headers: headers() });
    return r.json();
  },

  async getKnowledgeStats(): Promise<any> {
    const r = await fetch(`${BASE}/knowledge/stats`, { headers: headers() });
    return r.json();
  },

  async getStudyPlan(): Promise<any> {
    const r = await fetch(`${BASE}/knowledge/study-plan`, { headers: headers() });
    return r.json();
  },

  async getKnowledgeGaps(): Promise<any> {
    const r = await fetch(`${BASE}/patterns/gaps`, { headers: headers() });
    return r.json();
  },

  async getGeneratedTools(): Promise<any> {
    const r = await fetch(`${BASE}/tools`, { headers: headers() });
    return r.json();
  },

  async getDriftHistory(limit = 20): Promise<any> {
    const r = await fetch(`${BASE}/personality/drift/history?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  // ── Phase 6: Polish ──────────────────────────────────────────────

  async chat(message: string): Promise<any> {
    const r = await fetch(`${BASE}/chat?message=${encodeURIComponent(message)}`, { method: "POST", headers: headers() });
    return r.json();
  },

  async getChatHistory(limit = 50): Promise<any> {
    const r = await fetch(`${BASE}/chat/history?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  async generateReport(target: string): Promise<any> {
    const r = await fetch(`${BASE}/report/generate?target=${encodeURIComponent(target)}`, { method: "POST", headers: headers() });
    return r.json();
  },

  async loadAttack(): Promise<any> {
    const r = await fetch(`${BASE}/attack/load`, { method: "POST", headers: headers() });
    return r.json();
  },

  async getAttackStats(): Promise<any> {
    const r = await fetch(`${BASE}/attack/stats`, { headers: headers() });
    return r.json();
  },

  async getAttackTechniques(tactic?: string): Promise<any> {
    const url = tactic ? `${BASE}/attack/techniques?tactic=${tactic}` : `${BASE}/attack/techniques`;
    const r = await fetch(url, { headers: headers() });
    return r.json();
  },

  async mapAttackFindings(target: string): Promise<any> {
    const r = await fetch(`${BASE}/attack/map?target=${encodeURIComponent(target)}`, { method: "POST", headers: headers() });
    return r.json();
  },

  async getAttackCoverage(target: string): Promise<any> {
    const r = await fetch(`${BASE}/attack/coverage/${encodeURIComponent(target)}`, { headers: headers() });
    return r.json();
  },

  async getAuditChain(limit = 50): Promise<any> {
    const r = await fetch(`${BASE}/audit/chain?limit=${limit}`, { headers: headers() });
    return r.json();
  },

  async verifyAudit(): Promise<any> {
    const r = await fetch(`${BASE}/audit/verify`, { headers: headers() });
    return r.json();
  },

  // ── Threat Intelligence ──────────────────────────────────────────

  async getThreatStats(): Promise<any> {
    const r = await fetch(`${BASE}/threat/stats`, { headers: headers() });
    return r.json();
  },

  async getOWASP(): Promise<any> {
    const r = await fetch(`${BASE}/threat/owasp`, { headers: headers() });
    return r.json();
  },

  async getCVEs(limit = 50, severity?: string): Promise<any> {
    const url = severity ? `${BASE}/threat/cves?limit=${limit}&severity=${severity}` : `${BASE}/threat/cves?limit=${limit}`;
    const r = await fetch(url, { headers: headers() });
    return r.json();
  },

  async fullThreatUpdate(): Promise<any> {
    const r = await fetch(`${BASE}/threat/update-all`, { method: "POST", headers: headers() });
    return r.json();
  },

  async newTorCircuit(): Promise<any> {
    const r = await fetch(`${BASE}/tor/new-circuit`, { method: "POST", headers: headers() });
    return r.json();
  },

  async discoverOnions(query?: string): Promise<any> {
    const url = query ? `${BASE}/onion/discover?query=${query}` : `${BASE}/onion/discover`;
    const r = await fetch(url, { headers: headers() });
    return r.json();
  },

  async classifyOnion(url: string): Promise<any> {
    const r = await fetch(`${BASE}/onion/classify?url=${encodeURIComponent(url)}`, { method: "POST", headers: headers() });
    return r.json();
  },

  async getI2PStatus(): Promise<any> {
    const r = await fetch(`${BASE}/i2p/status`, { headers: headers() });
    return r.json();
  },

  // ── Phase 7: Exploitation ───────────────────────────────────────

  async getExploitModules(): Promise<any> {
    const r = await fetch(`${BASE}/exploit/modules`, { headers: headers() });
    return r.json();
  },

  async getExploitTargets(): Promise<any> {
    const r = await fetch(`${BASE}/exploit/targets`, { headers: headers() });
    return r.json();
  },

  async attemptExploit(target: string, finding_id: string, module_id: string): Promise<any> {
    const r = await fetch(`${BASE}/exploit/attempt`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        target,
        finding: { id: finding_id, class: module_id },
        context: { module_id },
        personality: {},
      }),
    });
    return r.json();
  },

  async autoExploit(target: string): Promise<any> {
    const r = await fetch(`${BASE}/exploit/auto`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ target, context: {}, personality: {} }),
    });
    return r.json();
  },

  async getExploitAttempts(): Promise<any> {
    const r = await fetch(`${BASE}/exploit/attempts`, { headers: headers() });
    return r.json();
  },

  async getExploitAttempt(id: string): Promise<any> {
    const r = await fetch(`${BASE}/exploit/attempts/${id}`, { headers: headers() });
    return r.json();
  },

  async getExploitLibrary(): Promise<any> {
    const r = await fetch(`${BASE}/exploit/library`, { headers: headers() });
    return r.json();
  },
};