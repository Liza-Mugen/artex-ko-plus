import { http } from "@/lib/api";
import type { FindingStatus, Severity } from "@/lib/types";

export type DefenseState = "unplanned" | "untested" | "current" | "stale";
export type DetectionResult = "detected" | "missed" | "not_tested";
export type PreventionResult = "blocked" | "not_blocked" | "not_tested";
export type RuleFormat = "query" | "sigma" | "other" | "event_filter";

export interface DefensePlanFields {
  hypothesis: string;
  log_source: string;
  rule_format: RuleFormat;
  rule_text: string;
  remediation: string;
}

export interface DefensePlan extends DefensePlanFields {
  finding_id: string;
  revision: number;
  updated_at: string;
}

export interface DefenseValidation {
  id: string;
  finding_id: string;
  plan_revision: number;
  evidence_version: number;
  source_fingerprint: string;
  plan_snapshot: DefensePlan;
  detection: DetectionResult;
  prevention: PreventionResult;
  evidence: string;
  observed_at: string;
  notes: string;
  created_at: string;
}

export interface DefenseScenario {
  id: string;
  state: "current" | "stale";
  evidence_version: number;
  source_fingerprint: string;
  created_at: string;
  title: string;
  attack_steps: {
    id: string;
    description: string;
    basis: "observed" | "hypothetical";
    evidence: string;
  }[];
  stages: {
    id: string;
    attack_step_id: string;
    title: string;
    equipment: {
      kind: string;
      presence: "unknown" | "present" | "absent";
      basis: string;
    }[];
    log_sources: string[];
    required_fields: string[];
    rule_draft: { format: "spl"; query: string; rationale: string };
    benign_baseline: string;
    success_criteria: string;
    limitations: string[];
  }[];
}

export interface FindingDefense {
  source_fingerprint: string;
  plan: DefensePlan | null;
  suggested_hypothesis: string;
  scenario: DefenseScenario | null;
  evidence_version: number;
  validations: DefenseValidation[];
  state: DefenseState;
}

export interface DefenseValidationInput {
  expected_source_fingerprint: string;
  plan_revision: number;
  expected_evidence_version: number;
  detection: DetectionResult;
  prevention: PreventionResult;
  evidence: string;
  observed_at: string;
  notes: string;
}

export interface PurpleOverview {
  stats: {
    total_findings: number;
    planned: number;
    validated: number;
    needs_revalidation: number;
    detected: number;
    missed: number;
    blocked: number;
    execution_total: number;
    execution_detected: number;
    execution_missed: number;
    execution_blocked: number;
    execution_inconclusive: number;
  };
  items: {
    finding_id: string;
    name: string;
    vulnclass: string;
    severity: Severity;
    finding_status: FindingStatus;
    state: DefenseState;
    plan_revision: number;
    detection: DetectionResult;
    prevention: PreventionResult;
    updated_at: string;
    execution_id?: string;
    execution_state: "none" | "current" | "stale";
    execution_status?: "pending" | "running" | "completed" | "failed" | "stopped";
    execution_detection?: "detected" | "missed" | "inconclusive";
    execution_prevention?: "blocked" | "not_blocked" | "inconclusive";
  }[];
  total: number;
  page: number;
  limit: number;
}

const defensePath = (id: string) => `/exploration/findings/${encodeURIComponent(id)}/defense`;

export const purpleApi = {
  findingDefense: (id: string) => http<FindingDefense>(defensePath(id)),
  generateScenario: (id: string) => http<FindingDefense>(`${defensePath(id)}/scenario/generate`, { method: "POST" }),
  savePlan: (id: string, fields: DefensePlanFields, expectedRevision: number) =>
    http<FindingDefense>(defensePath(id), {
      method: "PUT",
      body: JSON.stringify({ ...fields, expected_revision: expectedRevision }),
    }),
  recordValidation: (id: string, input: DefenseValidationInput) =>
    http<FindingDefense>(`${defensePath(id)}/validations`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  overview: (page: number, limit: number) => http<PurpleOverview>(`/purple/overview?page=${page}&limit=${limit}`),
};
