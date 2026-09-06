/* PITBULL Response Engine API client — types and fetch helpers */
import { api } from "./api";

// ── Types ────────────────────────────────────────────────────────────

export interface ResponseStatus {
  running: boolean;
  stats: {
    total_actions: number;
    total_blocked_by_rate_limit: number;
    total_pending_approval: number;
    total_auto_reversed: number;
    by_action: Record<string, number>;
    by_attack_type: Record<string, number>;
  };
  active_actions: number;
  pending_approvals: number;
  action_types: number;
  response_rules: number;
}

export interface ResponseAction {
  action_id: string;
  timestamp: number;
  action: string;
  attack_type: string;
  source_ip: string;
  status: string;
  details: string;
}

export interface PendingApproval {
  approval_id: string;
  action: string;
  attack_type: string;
  source_ip: string;
  queued_at: number;
}

export interface ResponseRule {
  attack_type: string;
  actions: string[];
}

export interface ActionMeta {
  level: number;
  destructive: boolean;
  reversible: boolean;
  auto: boolean;
}

export interface ResponseRules {
  rules: Record<string, string[]>;
  actions: Record<string, ActionMeta>;
}

// ── API calls ────────────────────────────────────────────────────────

export const responseApi = {
  status: () => api.get("/response/status") as Promise<ResponseStatus>,
  history: (limit = 50) => api.get(`/response/history?limit=${limit}`) as Promise<{ actions: ResponseAction[] }>,
  pending: () => api.get("/response/pending") as Promise<{ pending: PendingApproval[] }>,
  approve: (id: string) => api.post(`/response/approve/${id}`, {}),
  reject: (id: string) => api.post(`/response/reject/${id}`, {}),
  rules: () => api.get("/response/rules") as Promise<ResponseRules>,
};