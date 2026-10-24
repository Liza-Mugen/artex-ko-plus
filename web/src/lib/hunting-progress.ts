import type { HuntingRun } from "@/lib/hunting-api";

export const HUNTING_PHASES = [
  { id: "research", label: "리서치", description: "공개 자료와 출처 조사" },
  { id: "design", label: "시나리오", description: "공격 가설·탐지 질문 설계" },
  { id: "investigation", label: "Splunk 헌팅", description: "허용 로그의 자율 조사" },
  { id: "verification", label: "근거 판정", description: "원문 검증과 남은 확인" },
] as const;

export type HuntingPhaseId = (typeof HUNTING_PHASES)[number]["id"];
export type HuntingPhaseStatus =
  | "idle"
  | "pending"
  | "running"
  | "completed"
  | "insufficient_data"
  | "failed"
  | "cancelled"
  | "interrupted";

export interface HuntingPhaseProgress {
  id: HuntingPhaseId;
  label: string;
  description: string;
  status: HuntingPhaseStatus;
  statusLabel: string;
}

const STATUS_LABELS: Record<HuntingPhaseStatus, string> = {
  idle: "시작 전",
  pending: "대기",
  running: "진행 중",
  completed: "완료",
  insufficient_data: "자료 부족",
  failed: "실패",
  cancelled: "중지",
  interrupted: "중단",
};

const PHASE_INDEX: Record<string, number> = {
  research: 0,
  researching: 0,
  design: 1,
  designing: 1,
  scenario: 1,
  investigation: 2,
  investigate: 2,
  investigating: 2,
  hunting: 2,
  verification: 3,
  verify: 3,
  verifying: 3,
};
const ACTIVE = new Set(["running", "researching", "designing", "investigating", "verifying"]);
const STOPPED: Record<string, HuntingPhaseStatus> = {
  failed: "failed",
  model_error: "failed",
  cancelled: "cancelled",
  interrupted: "interrupted",
  budget_exhausted: "interrupted",
};

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function phaseIndex(value: unknown): number {
  return typeof value === "string" && Object.hasOwn(PHASE_INDEX, value) ? PHASE_INDEX[value] : -1;
}

/** Progress is execution progress, never a claim that an intrusion succeeded. */
export function getHuntingProgress(run: HuntingRun | null): HuntingPhaseProgress[] {
  const states: HuntingPhaseStatus[] = HUNTING_PHASES.map(() => (run ? "pending" : "idle"));
  const labels: Partial<Record<number, string>> = {};
  if (run && run.status !== "queued") {
    // Live API events wrap the engine event in payload. Evidence collections are
    // stored directly, while exported results contain flat engine events.
    const events = [
      ...(run.result?.events ?? []).map((event) => ({ kind: event.kind, stage: event.stage })),
      ...(run.events ?? []).map((event) => ({ kind: event.kind, stage: record(event.payload)?.stage })),
    ];
    const completed = new Set<number>();
    let reached = -1;
    let partialVerification = false;
    let verificationStarted = false;
    for (const event of events) {
      if (event.kind === "partial_verification") {
        partialVerification = true;
        continue;
      }
      const phase = event.kind === "evidence_collection" ? 2 : phaseIndex(event.stage);
      if (phase >= 0) reached = Math.max(reached, phase);
      if (phase === 3 && event.kind === "started") verificationStarted = true;
      if (event.kind === "research_completed") {
        completed.add(0);
        reached = Math.max(reached, 0);
      }
      if (event.kind === "design_completed") {
        completed.add(1);
        reached = Math.max(reached, 1);
      }
    }

    const resultPhase = phaseIndex(run.result?.stage);
    const statusPhase = phaseIndex(run.status);
    let current = Math.max(reached, resultPhase, statusPhase);
    const stopStatus = Object.hasOwn(STOPPED, run.status) ? STOPPED[run.status] : undefined;
    if (stopStatus && partialVerification && !verificationStarted) {
      // A best-effort check of saved evidence after a failed investigation is
      // not the normal final phase and cannot make the hunt appear complete.
      current = Math.min(current, 2);
      labels[3] = "부분 판정";
    }
    if (current < 0 && ACTIVE.has(run.status)) current = 0;

    // Reaching a later normal phase proves that preceding phases passed their
    // validation. A nonempty result alone does not: failed validation preserves
    // partial research/design objects too.
    for (let index = 0; index < current; index++) states[index] = "completed";
    for (const index of completed) states[index] = "completed";

    if (current >= 0) {
      if (stopStatus && !completed.has(current)) {
        states[current] = stopStatus;
        if (run.status === "budget_exhausted") labels[current] = "한도 도달";
        if (run.status === "model_error") labels[current] = "모델 오류";
      } else if (run.status === "insufficient_data" && current === 3) {
        states[3] = "insufficient_data";
      } else if (run.status === "completed" && current === 3) {
        states[3] = "completed";
      } else if (ACTIVE.has(run.status) && !completed.has(current)) {
        states[current] = "running";
      }
    }
  }
  return HUNTING_PHASES.map((phase, index) => ({
    ...phase,
    status: states[index],
    statusLabel: labels[index] ?? STATUS_LABELS[states[index]],
  }));
}
