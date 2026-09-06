/* PITBULL Sentinel API client — types and fetch helpers */
import { api } from "./api";

// ── Types ────────────────────────────────────────────────────────────

export interface SentinelStatus {
  status: "running" | "stopped";
  threat_level: "NORMAL" | "SUSPICIOUS" | "ELEVATED" | "HIGH" | "CRITICAL";
  stats: {
    total_events: number;
    total_attacks: number;
    blocked_ips: number;
    active_attackers: number;
  };
  uptime: number;
}

export interface AttackEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  attack_type: string;
  technique_id: string;
  technique_name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  evidence: string;
  details: string;
  blocked: boolean;
}

export interface AttackerProfile {
  ip: string;
  first_seen: string;
  last_seen: string;
  attack_count: number;
  attack_types: string[];
  techniques_used: string[];
  is_blocked: boolean;
  threat_level: string;
}

export interface BlockedIP {
  ip: string;
  blocked_at: string;
  reason: string;
  attack_type: string;
}

// ── API calls ────────────────────────────────────────────────────────

export const sentinelApi = {
  status: () => api.get("/sentinel/status"),
  attacks: (limit = 50) => api.get(`/sentinel/attacks?limit=${limit}`),
  attackers: () => api.get("/sentinel/attackers"),
  blocked: () => api.get("/sentinel/blocked"),
  block: (ip: string) => api.post("/sentinel/block", { ip }),
  unblock: (ip: string) => api.post("/sentinel/unblock", { ip }),
  whitelist: () => api.get("/sentinel/whitelist"),
  whitelistAdd: (ip: string) => api.post("/sentinel/whitelist/add", { ip }),
  whitelistRemove: (ip: string) => api.post("/sentinel/whitelist/remove", { ip }),
  investigate: (ip: string) => api.get(`/sentinel/investigate/${ip}`),
  feedUrl: "/api/v1/sentinel/feed",
};

// ── Labyrinth API ────────────────────────────────────────────────────

export interface LabyrinthStatus {
  state: "idle" | "arming" | "active" | "engaged" | "eroding" | "post_incident";
  mode: string;
  mirror_nodes: number;
  mirror_edges: number;
  attackers_tracked: number;
  active_attackers: number;
  fake_successes_served: number;
  dead_ends_served: number;
  confidence_crises_detected: number;
  activated_at: string | null;
}

export const labyrinthApi = {
  status: () => api.get("/labyrinth/status"),
  arm: (scale = 1.0) => api.post(`/labyrinth/arm`, { scale }),
  disarm: () => api.post("/labyrinth/disarm"),
  mirror: () => api.get("/labyrinth/mirror"),
  validate: () => api.get("/labyrinth/validate"),
  attackers: () => api.get("/labyrinth/attackers"),
  logs: (limit = 50) => api.get(`/labyrinth/logs?limit=${limit}`),
  feedUrl: "/api/v1/labyrinth/feed",
};