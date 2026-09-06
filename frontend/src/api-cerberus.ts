/* PITBULL Cerberus API client — types and fetch helpers */
import { api } from "./api";

// ── Types ────────────────────────────────────────────────────────────

export interface CerberusStatus {
  status: string;
  active_campaign: CampaignStatus | null;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  new_findings: number;
  confirmed_findings: number;
  reported_findings: number;
  fixed_findings: number;
}

export interface CampaignStatus {
  campaign_id: string;
  target: string;
  strategy: string;
  target_type: string;
  iterations_requested: number;
  iterations_run: number;
  crashes_found: number;
  unique_crashes: number;
  hangs_found: number;
  errors_found: number;
  coverage_edges: number;
  started_at: string;
  completed_at?: string;
  status: string;
  crashes: CrashData[];
  events: CampaignEvent[];
}

export interface CampaignEvent {
  timestamp: string;
  type: string;
  data: any;
}

export interface CrashData {
  input: string;
  input_b64: string;
  timestamp: string;
  exit_code?: number;
  stdout?: string;
  stderr?: string;
  crash?: boolean;
  signal?: number;
  signal_name?: string;
  timeout?: boolean;
  hang?: boolean;
  possible_crash?: boolean;
  error?: string;
}

export interface ZeroDayFinding {
  finding_id: string;
  target: string;
  campaign_id?: string;
  vuln_type: string;
  cwe_class: string;
  cwe_name?: string;
  severity: string;
  description: string;
  poc_code: string;
  stack_trace: string;
  stack_trace_hash?: string;
  signal?: number;
  signal_name?: string;
  exit_code?: number;
  attack_techniques?: string[];
  exploitability?: string;
  discovered_at: string;
  status: string;
  updated_at?: string;
}

export interface TargetAnalysis {
  file_path?: string;
  file_size?: number;
  analyzed_at: string;
  binary_type?: string;
  architecture?: string;
  bits?: number;
  endian?: string;
  elf_type?: string;
  linked_libraries?: string[];
  entry_points?: string[];
  input_vectors?: InputVector[];
  llm_analysis?: any;
  error?: string;
  // Protocol/API fields
  host?: string;
  port?: number;
  base_url?: string;
  detected_protocol?: string;
  banner?: string;
  endpoints?: any[];
  openapi_spec?: boolean;
  api_spec_url?: string;
}

export interface InputVector {
  type: string;
  description: string;
}

export interface CWEClass {
  cwe_id: string;
  name: string;
  severity: string;
  attack_techniques: string[];
}

export interface Analytics {
  total_findings: number;
  by_severity: Record<string, number>;
  by_cwe: Record<string, number>;
  by_target: Record<string, number>;
  by_status: Record<string, number>;
  by_date: Record<string, number>;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

// ── API calls ────────────────────────────────────────────────────────

export const cerberusApi = {
  status: () => api.get("/cerberus/status"),

  analyze: (target: string, target_type: string) =>
    api.post("/cerberus/analyze", { target, target_type }),

  startFuzz: (target: string, strategy: string, iterations: number, delay_ms: number, target_type: string = "binary") =>
    api.post("/cerberus/fuzz/start", { target, strategy, iterations, delay_ms, target_type }),

  stopFuzz: () => api.post("/cerberus/fuzz/stop"),

  fuzzStatus: () => api.get("/cerberus/fuzz/status"),

  findings: (severity?: string, target?: string, status?: string, limit = 100) => {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (target) params.set("target", target);
    if (status) params.set("status", status);
    params.set("limit", String(limit));
    return api.get(`/cerberus/findings?${params.toString()}`);
  },

  getFinding: (id: string) => api.get(`/cerberus/findings/${id}`),

  updateFinding: (id: string, status: string) =>
    fetch(`/api/v1/cerberus/findings/${id}`, {
      method: "PATCH",
      headers: {
        "X-API-Key": localStorage.getItem("pitbull_api_key") || "pitbull-explorer-dev-key-2026",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ status }),
    }).then((r) => r.json()),

  generateReport: (id: string) => api.get(`/cerberus/findings/${id}/report`),

  exportFindings: (format: string = "json") => api.get(`/cerberus/findings/export?format=${format}`),

  cweClasses: () => api.get("/cerberus/cwe/classes"),

  analytics: () => api.get("/cerberus/analytics"),

  feedUrl: "/api/v1/cerberus/feed",
};