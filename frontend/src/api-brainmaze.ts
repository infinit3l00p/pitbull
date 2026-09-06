/* PITBULL BrainMaze API client — types and fetch helpers */
import { api } from "./api";

// ── Types ────────────────────────────────────────────────────────────

export interface BrainMazeStatus {
  total_attackers: number;
  active_attackers: number;
  trails_deployed: number;
  wasters_deployed: number;
  paranoia_injections: number;
  active_personas: number;
  avg_confusion_score: number;
  attackers: AttackerConfusion[];
  personas: ActivePersona[];
  techniques: TechniqueCategory[];
}

export interface AttackerConfusion {
  attacker_ip: string;
  confusion_score: number;
  phase: string;
  first_seen: string | null;
  last_update: string | null;
  time_in_system: number;
  commands_executed: number;
  commands_retried: number;
  dead_ends_hit: number;
  paranoia_indicators: number;
  active_techniques: string[];
  trails_deployed: number;
  wasters_deployed: number;
  paranoia_injections: number;
  persona_active: boolean;
  persona_type: string | null;
  technique_history_count: number;
}

export interface ActivePersona {
  attacker_ip: string;
  persona_name: string;
  persona_type: string;
  role: string;
  interactions: number;
  active: boolean;
  created_at: string;
}

export interface TechniqueCategory {
  category: string;
  techniques: TechniqueInfo[];
}

export interface TechniqueInfo {
  id: string;
  name: string;
  description: string;
}

export interface ConfusionHistory {
  attacker_ip: string;
  confusion_score: number;
  phase: string;
  technique_count: number;
  history: TechniqueEvent[];
}

export interface TechniqueEvent {
  timestamp: string;
  technique: string;
  confusion_score: number;
  phase: string;
  [key: string]: any;
}

export interface PersonaResponse {
  persona_name: string;
  persona_type: string;
  response: string;
  interaction_count: number;
}

export interface BrainMazeAnalytics {
  total_attackers: number;
  total_techniques_deployed: number;
  avg_confusion_score: number;
  max_confusion_score: number;
  total_time_wasted_seconds: number;
  technique_breakdown: Record<string, number>;
  phase_distribution: Record<string, number>;
  persona_interactions: number;
}

// ── API calls ────────────────────────────────────────────────────────

export const brainmazeApi = {
  status: () => api.get("/brainmaze/status"),
  techniques: () => api.get("/brainmaze/techniques"),
  analytics: () => api.get("/brainmaze/analytics"),
  attackerConfusion: (ip: string) => api.get(`/brainmaze/attacker/${ip}/confusion`),
  attackerHistory: (ip: string) => api.get(`/brainmaze/attacker/${ip}/history`),
  personaInteractions: (ip?: string) =>
    api.get(ip ? `/brainmaze/persona/interactions?attacker_ip=${ip}` : "/brainmaze/persona/interactions"),
  personaSelect: (attacker_ip: string, persona_type?: string) =>
    api.post("/brainmaze/persona/select", { attacker_ip, persona_type }),
  personaRespond: (attacker_ip: string, attacker_input: string, context?: any) =>
    api.post("/brainmaze/persona/respond", { attacker_ip, attacker_input, context }),
  trailsGenerate: (attacker_ip: string, trail_type: string, opts?: { domain?: string; filename?: string; count?: number }) =>
    api.post("/brainmaze/trails/generate", { attacker_ip, trail_type, ...opts }),
  paranoiaInject: (attacker_ip: string, paranoia_type: string) =>
    api.post("/brainmaze/paranoia/inject", { attacker_ip, paranoia_type }),
  wastersGenerate: (attacker_ip: string, waster_type: string, opts?: { name?: string; rows?: number; depth?: number; filename?: string }) =>
    api.post("/brainmaze/wasters/generate", { attacker_ip, waster_type, ...opts }),
  processCommand: (attacker_ip: string, command: string) =>
    api.post("/brainmaze/attacker/command", { attacker_ip, command }),
  processDeadEnd: (attacker_ip: string) =>
    api.post("/brainmaze/attacker/dead-end", { attacker_ip }),
  processTimeElapsed: (attacker_ip: string, seconds: number) =>
    api.post("/brainmaze/attacker/time-elapsed", { attacker_ip, seconds }),
  feedErosion: (ip: string) =>
    api.post(`/brainmaze/attacker/${ip}/feed-erosion`),
  feedUrl: "/api/v1/brainmaze/feed",
};