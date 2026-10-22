import { http } from "@/lib/api";
import type { InvestigationAgentRun, InvestigationAgentRunSummary } from "@/lib/investigation-agent-api";
import type {
  InvestigationInput,
  InvestigationPreview,
  InvestigationRecord,
  InvestigationScope,
} from "@/lib/investigation-api";

export interface DefensiveCaseSummary {
  id: string;
  title: string;
  question: string;
  source_kind: "file" | "splunk";
  scope: InvestigationScope;
  summary: string;
  observed_count: number;
  known_artex_count: number;
  complete: boolean;
  created_at: string;
}

export type DefensiveCase = Omit<
  InvestigationRecord,
  "finding_id" | "finding_snapshot" | "evidence_version" | "source_fingerprint"
> & {
  finding_id?: string;
  finding_snapshot?: Record<string, unknown>;
  evidence_version?: number;
  source_fingerprint?: string;
};
export type DefensiveCaseInput = Omit<InvestigationInput, "expected_evidence_version" | "expected_source_fingerprint">;

const casePath = (id: string) => `/defensive/cases/${encodeURIComponent(id)}`;
const runPath = (id: string) => `${casePath(id)}/runs`;

export const defensiveApi = {
  list: () => http<{ cases: DefensiveCaseSummary[]; total: number; history_truncated?: boolean }>("/defensive/cases"),
  get: (id: string) => http<DefensiveCase>(casePath(id)),
  delete: (id: string) => http<{ deleted: string }>(casePath(id), { method: "DELETE" }),
  create: (input: DefensiveCaseInput) =>
    http<DefensiveCase>("/defensive/cases", { method: "POST", body: JSON.stringify(input) }),
  preview: (input: DefensiveCaseInput) =>
    http<InvestigationPreview>("/defensive/cases/preview", { method: "POST", body: JSON.stringify(input) }),
  export: (id: string) => http<Blob>(`${casePath(id)}/export`, undefined, "blob"),
};

// The shared investigation view receives the same read-only agent contract.
// Its first argument is unused here: standalone cases have no finding parent.
export const defensiveAgentApi = {
  list: (_finding: string, caseId: string) =>
    http<{ runs: InvestigationAgentRunSummary[]; history_truncated?: boolean }>(runPath(caseId)),
  get: (_finding: string, caseId: string, runId: string) =>
    http<InvestigationAgentRun>(`${runPath(caseId)}/${encodeURIComponent(runId)}`),
  create: (_finding: string, caseId: string, input: { question: string }) =>
    http<InvestigationAgentRun>(runPath(caseId), { method: "POST", body: JSON.stringify(input) }),
  cancel: (_finding: string, caseId: string, runId: string) =>
    http<InvestigationAgentRun>(`${runPath(caseId)}/${encodeURIComponent(runId)}/cancel`, { method: "POST" }),
  export: (_finding: string, caseId: string, runId: string) =>
    http<Blob>(`${runPath(caseId)}/${encodeURIComponent(runId)}/export`, undefined, "blob"),
};

export interface AegisOverview {
  offensive: { tasks: number; active_tasks: number; findings: number; assets: number };
  defensive: { cases: number; active_runs: number; sources: number; observed_events: number };
  closed_loop: { cycles: number };
  generated_at: string;
}

export const aegisApi = { overview: () => http<AegisOverview>("/aegis/overview") };
