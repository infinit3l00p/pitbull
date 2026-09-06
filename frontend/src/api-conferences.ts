/* PITBULL Conference Watcher API client — types and fetch helpers */

const API_KEY = localStorage.getItem("pitbull_api_key") || "pitbull-explorer-dev-key-2026";
const BASE = "/api/v1/conferences";

function headers() {
  return { "X-API-Key": API_KEY, "Content-Type": "application/json" };
}

// ── Types ────────────────────────────────────────────────────────────

export interface Conference {
  id: string;
  name: string;
  location: string;
  start_date: string;
  end_date: string;
  website: string;
  focus_areas: string[];
  tier: 1 | 2;
  status: "upcoming" | "ongoing" | "past";
  days_until?: number;
}

export interface ConferenceListResponse {
  total: number;
  conferences: Conference[];
}

export interface UpcomingResponse {
  days: number;
  count: number;
  conferences: Conference[];
}

export interface Paper {
  paper_id: string;
  title: string;
  authors: string[];
  abstract: string;
  published: string;
  arxiv_url: string;
  doi?: string;
  categories: string[];
  fetched_at: string;
}

export interface PapersResponse {
  count: number;
  days: number;
  papers: Paper[];
}

export interface PaperSearchResponse {
  query: string;
  count: number;
  papers: Paper[];
}

export interface PaperScanResponse {
  status: string;
  papers_found: number;
  papers: { paper_id: string; title: string; arxiv_url: string; published: string }[];
}

export interface KnowledgeEntry {
  entry_id: string;
  title: string;
  description: string;
  source: string;
  source_url: string;
  technique_type: string;
  mitre_attack_ids: string[];
  tags: string[];
  relevance_score: number;
  added_at: string;
}

export interface KnowledgeListResponse {
  count: number;
  entries: KnowledgeEntry[];
}

export interface KnowledgeSearchResponse {
  query: string;
  count: number;
  entries: KnowledgeEntry[];
}

export interface ScanSummary {
  scan_id: string;
  conferences: {
    total: number;
    upcoming: number;
    ongoing: number;
    past: number;
  };
  papers: {
    fetched: number;
    stored: number;
    errors: number;
  };
  knowledge_base: {
    entries_created: number;
    errors: number;
  };
  errors: string[];
}

export interface WatcherStats {
  conferences: {
    total: number;
    by_status: { upcoming: number; ongoing: number; past: number };
    by_tier: Record<string, number>;
  };
  papers: { total_stored: number };
  knowledge_base: {
    total: number;
    types: string[];
    sources: string[];
  };
}

export interface CalendarResponse {
  months: number;
  total_events: number;
  calendar: Record<string, Conference[]>;
}

// ── API calls ────────────────────────────────────────────────────────

export const conferenceApi = {
  // Conferences
  list: async (): Promise<ConferenceListResponse> => {
    const r = await fetch(`${BASE}/`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  upcoming: async (days = 30): Promise<UpcomingResponse> => {
    const r = await fetch(`${BASE}/upcoming?days=${days}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  get: async (name: string): Promise<Conference> => {
    const r = await fetch(`${BASE}/${encodeURIComponent(name)}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  // Papers
  papers: async (days = 7): Promise<PapersResponse> => {
    const r = await fetch(`${BASE}/papers?days=${days}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  searchPapers: async (q: string): Promise<PaperSearchResponse> => {
    const r = await fetch(`${BASE}/papers/search?q=${encodeURIComponent(q)}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  scanPapers: async (maxPerKeyword = 5): Promise<PaperScanResponse> => {
    const r = await fetch(`${BASE}/papers/scan?max_per_keyword=${maxPerKeyword}`, {
      method: "POST",
      headers: headers(),
    });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  // Knowledge Base
  knowledge: async (filters?: {
    technique_type?: string;
    source?: string;
    tag?: string;
    limit?: number;
    offset?: number;
  }): Promise<KnowledgeListResponse> => {
    const params = new URLSearchParams();
    if (filters?.technique_type) params.set("technique_type", filters.technique_type);
    if (filters?.source) params.set("source", filters.source);
    if (filters?.tag) params.set("tag", filters.tag);
    if (filters?.limit) params.set("limit", String(filters.limit));
    if (filters?.offset) params.set("offset", String(filters.offset));
    const r = await fetch(`${BASE}/knowledge?${params}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  searchKnowledge: async (q: string): Promise<KnowledgeSearchResponse> => {
    const r = await fetch(`${BASE}/knowledge/search?q=${encodeURIComponent(q)}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  getKnowledge: async (entryId: string): Promise<KnowledgeEntry> => {
    const r = await fetch(`${BASE}/knowledge/${encodeURIComponent(entryId)}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  // Scan & Stats
  fullScan: async (): Promise<ScanSummary> => {
    const r = await fetch(`${BASE}/scan`, { method: "POST", headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  stats: async (): Promise<WatcherStats> => {
    const r = await fetch(`${BASE}/stats`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },

  calendar: async (months = 6): Promise<CalendarResponse> => {
    const r = await fetch(`${BASE}/calendar?months=${months}`, { headers: headers() });
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  },
};