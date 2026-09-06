/* PITBULL TrapCard API client — types and fetch helpers */
import { api } from "./api";

// ── Types ────────────────────────────────────────────────────────────

export interface TrapCardStatus {
  ssh_honeypot: {
    running: boolean;
    port: number;
    host: string;
    active_connections: number;
    total_connections: number;
    total_sessions: number;
  };
  web_honeypot: {
    running: boolean;
    endpoints: string[];
  };
  total_captures: number;
  total_sessions: number;
  total_attackers: number;
}

export interface Capture {
  capture_id: string;
  sha256: string;
  size: number;
  mime_type: string;
  filename: string;
  service: string;
  captured_at: string;
  file_path: string;
  source_ip: string;
  session_id: string;
  attack_techniques: any[];
  analysis?: any;
}

export interface CaptureDetail extends Capture {
  attack_techniques: Array<{
    technique_id: string;
    description: string;
    matched_pattern: string;
  }>;
  analysis?: {
    file_type: string;
    file_type_description: string;
    strings: string[];
    entropy: number;
    is_script: boolean;
    is_binary: boolean;
    signatures: Array<{ family: string; description: string }>;
  };
}

export interface AttackerSession {
  session_id: string;
  source_ip: string;
  service: string;
  first_seen: string;
  last_seen: string;
  log_path: string;
  tool_count: number;
  tools: Array<{
    sha256: string;
    filename: string;
    size: number;
    mime_type: string;
  }>;
}

export interface SessionDetail extends AttackerSession {
  recording: string | null;
  tools: Array<{
    sha256: string;
    filename: string;
    size: number;
    mime_type: string;
    capture_id: string;
    attack_techniques: string[];
  }>;
}

export interface TrapCardAnalytics {
  total_captures: number;
  total_sessions: number;
  total_attackers: number;
  by_type: Array<{ type: string; count: number }>;
  by_ip: Array<{ ip: string; count: number }>;
  by_day: Array<{ day: string; count: number }>;
  attack_mapping: Array<{ technique: string; count: number }>;
}

export interface FeedEvent {
  type: string;
  session_id?: string;
  source_ip?: string;
  command?: string;
  filename?: string;
  sha256?: string;
  size?: number;
  service?: string;
  timestamp?: number;
  username?: string;
  password?: string;
  port?: number;
  message?: string;
}

// ── API calls ────────────────────────────────────────────────────────

export const trapcardApi = {
  status: () => api.get("/trapcard/status"),
  captures: (limit = 50, offset = 0) =>
    api.get(`/trapcard/captures?limit=${limit}&offset=${offset}`),
  capture: (captureId: string) => api.get(`/trapcard/captures/${captureId}`),
  sessions: (limit = 50, offset = 0) =>
    api.get(`/trapcard/sessions?limit=${limit}&offset=${offset}`),
  session: (sessionId: string) => api.get(`/trapcard/sessions/${sessionId}`),
  startSSH: (port = 2222, host = "0.0.0.0") =>
    api.post(`/trapcard/ssh/start?port=${port}&host=${host}`),
  stopSSH: () => api.post("/trapcard/ssh/stop"),
  startWeb: () => api.post("/trapcard/web/start"),
  stopWeb: () => api.post("/trapcard/web/stop"),
  analytics: () => api.get("/trapcard/analytics"),
  feedUrl: "/api/v1/trapcard/feed",
};