"use client";

import { CheckIcon, CircleIcon, CirclePauseIcon, CircleXIcon, LoaderCircleIcon, TriangleAlertIcon } from "lucide-react";

import type { HuntingRun } from "@/lib/hunting-api";
import { huntingStatusLabel } from "@/lib/hunting-api";
import { getHuntingProgress, type HuntingPhaseId, type HuntingPhaseStatus } from "@/lib/hunting-progress";
import { cn } from "@/lib/utils";

const PHASE_ICONS: Record<HuntingPhaseStatus, typeof CircleIcon> = {
  idle: CircleIcon,
  pending: CircleIcon,
  running: LoaderCircleIcon,
  completed: CheckIcon,
  insufficient_data: TriangleAlertIcon,
  failed: CircleXIcon,
  cancelled: CirclePauseIcon,
  interrupted: CirclePauseIcon,
};

export function HuntingProgress({
  run,
  loading = false,
  activePhase,
  onPhaseSelect,
  resultTabsId,
}: {
  run: HuntingRun | null;
  loading?: boolean;
  activePhase: HuntingPhaseId;
  onPhaseSelect: (phase: HuntingPhaseId) => void;
  resultTabsId: string;
}) {
  const phases = getHuntingProgress(run);
  const summary = loading ? "실행 불러오는 중" : huntingStatusLabel(run?.status ?? "새 헌팅 준비");
  return (
    <section
      aria-label="4개 엔진 진행 상태"
      className="sticky top-12 z-20 space-y-3 rounded-xl border bg-background/95 p-3 shadow-sm backdrop-blur-sm md:p-4"
    >
      <div className="flex items-center justify-between gap-3 text-xs">
        <h2 className="font-semibold text-sm">엔진 진행 상태</h2>
        <p role="status" className="text-muted-foreground">
          {summary}
        </p>
      </div>
      <ol className="grid grid-cols-4 gap-1.5 md:gap-3">
        {phases.map((phase, index) => {
          const status = loading ? "pending" : phase.status;
          const Icon = PHASE_ICONS[status];
          return (
            <li key={phase.id} className="min-w-0">
              <button
                type="button"
                disabled={!run || loading}
                onClick={() => onPhaseSelect(phase.id)}
                aria-label={`${phase.label}: ${loading ? "불러오는 중" : phase.statusLabel}. 결과 탭 열기`}
                aria-current={status === "running" ? "step" : undefined}
                aria-pressed={!!run && activePhase === phase.id}
                aria-controls={run ? resultTabsId : undefined}
                className={cn(
                  "h-full w-full min-w-0 space-y-2 rounded-lg border p-2 text-left transition-colors hover:border-sky-500/60 focus-visible:outline-2 focus-visible:outline-sky-500 focus-visible:outline-offset-4 disabled:cursor-default disabled:opacity-60 motion-reduce:transition-none md:p-3",
                  status === "completed" && "border-emerald-500/25 bg-emerald-500/5",
                  ["insufficient_data", "cancelled", "interrupted"].includes(status) &&
                    "border-amber-500/30 bg-amber-500/5",
                  status === "failed" && "border-destructive/30 bg-destructive/5",
                  run && activePhase === phase.id && status !== "running" && "ring-1 ring-foreground/30",
                  status === "running" &&
                    "border-sky-500 bg-sky-500/15 text-sky-900 shadow-sm ring-2 ring-sky-500/70 dark:bg-sky-500/20 dark:text-sky-100",
                )}
              >
                <span className="flex flex-wrap items-center gap-1.5 font-medium text-[11px] md:text-sm">
                  <span className="hidden text-muted-foreground md:inline">0{index + 1}</span>
                  {phase.label}
                </span>
                <span className="flex flex-wrap items-center gap-1 text-[11px] md:text-xs">
                  <Icon
                    aria-hidden="true"
                    className={cn(
                      "size-3 shrink-0 md:size-3.5",
                      status === "running" && "animate-spin motion-reduce:animate-none",
                    )}
                  />
                  <span>{loading ? "불러오는 중" : phase.statusLabel}</span>
                  {status === "running" ? (
                    <span
                      aria-hidden="true"
                      className="inline-flex items-center gap-1 rounded bg-sky-600 px-1 py-0.5 font-semibold text-[8px] text-white leading-none"
                    >
                      <span className="size-1 rounded-full bg-white motion-safe:animate-pulse" />
                      LIVE
                    </span>
                  ) : null}
                </span>
                <span className="hidden text-muted-foreground text-xs lg:block">{phase.description}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
