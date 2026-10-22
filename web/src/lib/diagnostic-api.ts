import { http } from "@/lib/api";

export type DiagnosticStatus = "queued" | "running" | "completed" | "partial" | "failed" | "cancelled" | "interrupted";
export type ExecutionStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "interrupted"
  | "unavailable";
export type FollowupStatus =
  | "pending"
  | "available"
  | "launching"
  | "running"
  | "completed"
  | "failed"
  | "needs_model"
  | "cancelled";

export interface DiagnosticTool {
  id: string;
  label: string;
  available: boolean;
  version?: string;
  backend?: string;
  detail?: string;
}

export interface DiagnosticExecution {
  id: string;
  tool: string;
  label?: string;
  backend?: string;
  version?: string;
  status: ExecutionStatus;
  started_at?: string;
  finished_at?: string;
  elapsed_ms?: number;
  exit_code?: number;
  error_kind?: string;
  error?: string;
  summary?: string;
  artifact_names: string[];
}

export interface DiagnosticObservation {
  id: string;
  kind: "service" | "endpoint";
  url: string;
  method: string;
  parameters: string[];
  status_code?: number;
  technologies: string[];
  sources: string[];
  confidence: "observed" | "inferred";
  evidence_ref: string;
  summary?: string;
}

export interface DiagnosticApiOperation {
  method: string;
  path: string;
  url: string;
  summary?: string;
  source_url: string;
  evidence_ref: string;
  verification: "observed_get" | "documented_unverified";
}

export interface DiagnosticCoverage {
  observed_get_urls: number;
  inferred_urls: number;
  http_requests: number;
  max_http_requests: number;
  distinct_urls_requested: number;
  max_distinct_urls: number;
  documented_operations: number;
  observed_documented_get_operations: number;
  unverified_documented_operations: number;
  scanner_candidates: number;
  limits: string[];
  exhaustive: false;
}

export interface DiagnosticCandidate {
  id: string;
  title: string;
  severity: string;
  url: string;
  method?: string;
  description: string;
  evidence_refs: string[];
  verification: "candidate";
}

export interface DiagnosticAttackPath {
  id: string;
  goal: string;
  target_url: string;
  status: "verification_required";
  steps: {
    url: string;
    status_code?: number;
    confidence: "observed" | "inferred";
    evidence_ref?: string;
    relation: string;
  }[];
  candidate_ids: string[];
  priority_basis?: string[];
  evidence_refs: string[];
  assessment: string;
  next_action: string;
}

export interface DiagnosticArtifact {
  name: string;
  sha256: string;
  size: number;
  content_type?: string;
}

export interface DiagnosticFollowup {
  status: FollowupStatus;
  task_id?: string;
  task_status?: string;
  error?: string;
  result?: {
    findings: { id: number | string; title: string; severity: string; summary?: string }[];
    findings_total?: number;
    findings_complete?: boolean;
    facts_count: number;
    discovery_facts_count?: number;
    new_facts_count?: number;
    blocked_intents?: number;
    recent_facts?: { id: number; summary: string; state: string }[];
    summary?: string;
  };
}

export interface DiagnosticRun {
  id: string;
  name: string;
  target_url: string;
  scope_urls?: string[];
  goal: string;
  status: DiagnosticStatus;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  tools: string[];
  timeout_seconds: number;
  max_urls: number;
  auto_followup: boolean;
  auth_context?: "anonymous" | "provided_bearer";
  llm_profile_ids: number[];
  executions: DiagnosticExecution[];
  observations: DiagnosticObservation[];
  api_operations?: DiagnosticApiOperation[];
  coverage?: DiagnosticCoverage;
  candidates: DiagnosticCandidate[];
  attack_paths?: DiagnosticAttackPath[];
  artifacts: DiagnosticArtifact[];
  warnings: string[];
  summary: string;
  error?: string;
  followup: DiagnosticFollowup;
}

export interface DiagnosticInput {
  name: string;
  target_url: string;
  scope_urls: string[];
  goal: string;
  tools: string[];
  timeout_seconds: number;
  max_urls: number;
  bearer_token?: string;
  auto_followup: boolean;
  llm_profile_ids: number[];
}

const base = "/offensive/diagnostics";
const runPath = (id: string) => `${base}/runs/${encodeURIComponent(id)}`;

export const diagnosticApi = {
  catalog: () =>
    http<{ tools: DiagnosticTool[]; provenance?: unknown[]; ready?: boolean; error?: string }>(`${base}/catalog`),
  list: (signal?: AbortSignal) => http<{ runs: DiagnosticRun[] }>(`${base}/runs`, { signal }),
  get: (id: string, signal?: AbortSignal) => http<DiagnosticRun>(runPath(id), { signal }),
  create: (input: DiagnosticInput) =>
    http<DiagnosticRun>(`${base}/runs`, { method: "POST", body: JSON.stringify(input) }),
  cancel: (id: string) => http<DiagnosticRun>(`${runPath(id)}/cancel`, { method: "POST" }),
  investigate: (id: string, profileIds: number[]) =>
    http<DiagnosticRun>(`${runPath(id)}/investigate`, {
      method: "POST",
      body: JSON.stringify({ llm_profile_ids: profileIds }),
    }),
  artifact: (id: string, name: string) =>
    http<Blob>(`${runPath(id)}/artifacts/${encodeURIComponent(name)}`, undefined, "blob"),
};
