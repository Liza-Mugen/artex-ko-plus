"use client";

import * as React from "react";

import { ExternalLinkIcon } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  type HuntingEvent,
  type HuntingResearchSource,
  type HuntingResult,
  type HuntingRun,
  huntingRunActive,
  huntingStatusLabel,
} from "@/lib/hunting-api";
import { HUNTING_PHASES, type HuntingPhaseId } from "@/lib/hunting-progress";
import type { InvestigationCollection, InvestigationEvent } from "@/lib/investigation-api";

const STAGE_LABELS: Record<string, string> = {
  research: "자료 조사",
  design: "공격 가설·탐지 질문 설계",
  investigation: "Splunk 근거 조사",
  hunting: "Splunk 근거 조사",
  investigate: "Splunk 근거 조사",
  verification: "근거 검증",
  verify: "근거 검증",
};
const ASSESSMENT_LABELS: Record<string, string> = {
  evidence_observed: "관련 근거 관측",
  observed: "관측 기록",
  inferred: "추론·추가 확인 필요",
  not_observed: "선택 범위에서 미관측",
  insufficient_data: "자료 부족",
};

function safeURL(value: string) {
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch {
    return null;
  }
}

function StringList({ values, label }: { values?: string[] | null; label: string }) {
  if (!values?.length) return null;
  return (
    <div className="space-y-1.5">
      <p className="font-medium text-sm">{label}</p>
      <ul className="list-disc space-y-1 pl-5 text-muted-foreground text-sm leading-relaxed">
        {values.map((value, index) => (
          <li key={`${index}-${value}`} className="whitespace-pre-wrap break-words">
            {value}
          </li>
        ))}
      </ul>
    </div>
  );
}

function SourceLinks({ ids, sources }: { ids?: string[] | null; sources: Map<string, HuntingResearchSource> }) {
  if (!ids?.length) return null;
  return (
    <div className="flex flex-wrap gap-2 text-xs">
      {ids.map((id) => {
        const source = sources.get(id);
        const url = source ? safeURL(source.url) : null;
        return url ? (
          <a
            key={id}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 break-all underline underline-offset-2"
          >
            {source?.title || id}
            <ExternalLinkIcon className="size-3 shrink-0" />
          </a>
        ) : (
          <span key={id} className="text-muted-foreground">
            출처 {id}
            {!source ? " (자료 연결 미확인)" : ""}
          </span>
        );
      })}
    </div>
  );
}

type IndexedEvidence = { event: InvestigationEvent; collection: InvestigationCollection };

function object(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function normalizedEvents(run: HuntingRun): HuntingEvent[] {
  if (!run.events?.length) return run.result?.events ?? [];
  return run.events.map((entry) => {
    const payload = object(entry.payload);
    const collection = object(payload?.collection);
    const stats = object(collection?.stats);
    return {
      sequence: entry.sequence,
      stage: typeof payload?.stage === "string" ? payload.stage : "investigation",
      kind: entry.kind,
      summary:
        typeof payload?.summary === "string"
          ? payload.summary
          : entry.kind === "evidence_collection"
            ? `Splunk 조회 근거를 보존했습니다${typeof stats?.selected === "number" ? ` · ${stats.selected}건` : ""}`
            : entry.kind,
      detail: typeof payload?.detail === "string" ? payload.detail : undefined,
      payload: entry.kind === "evidence_collection" ? entry.payload : payload?.payload,
      at: typeof payload?.at === "string" ? payload.at : entry.created_at,
    };
  });
}

function latestSnapshot<T>(events: HuntingEvent[], kind: string): T | undefined {
  for (let index = events.length - 1; index >= 0; index--) {
    if (events[index].kind === kind && object(events[index].payload)) return events[index].payload as T;
  }
  return undefined;
}

function EvidenceRefs({
  refs,
  index,
  conflicts,
  label,
}: {
  refs?: string[] | null;
  index: Map<string, IndexedEvidence>;
  conflicts: Set<string>;
  label: string;
}) {
  if (!refs?.length) return null;
  return (
    <div className="space-y-2">
      <p className="font-medium text-sm">{label}</p>
      {refs.slice(0, 20).map((ref) => {
        const item = index.get(ref);
        if (!item || conflicts.has(ref))
          return (
            <p
              key={ref}
              className="break-all rounded-md border border-amber-500/30 p-3 text-amber-700 text-xs dark:text-amber-300"
            >
              {ref} ·{" "}
              {conflicts.has(ref)
                ? "서로 다른 원문이 같은 ref를 사용합니다. 내보내기에서 원본을 대조하세요."
                : "현재 결과에서 원문을 연결하지 못했습니다."}
            </p>
          );
        const event = item.event;
        return (
          <details key={ref} className="min-w-0 rounded-md border p-3">
            <summary className="cursor-pointer break-all text-xs">
              <span className="font-medium">{event.id}</span> · {new Date(event.timestamp).toLocaleString()} ·{" "}
              {event.event_kind || "이벤트"}
              {event.known_artex ? " · 등록 ARTEX 검증 표식" : ""}
            </summary>
            <div className="mt-3 space-y-2 text-xs">
              <p className="break-all font-mono">ref: {ref}</p>
              <p className="break-all">
                {event.target}
                {event.path} · {event.action || "조치 미기록"} · {event.status || "상태 미기록"}
              </p>
              <p className="break-all text-muted-foreground">
                {event.file_name}:{event.line} · 수집 {new Date(item.collection.collected_at).toLocaleString()}
              </p>
              {event.known_artex ? (
                <p className="text-muted-foreground">
                  등록 검증 요청과 분리한 근거입니다. 표식만으로 요청자 신원이 인증되지는 않습니다.
                </p>
              ) : null}
              <p className="text-muted-foreground">원문 발췌입니다. 전체 원문은 JSON 내보내기에서 확인하세요.</p>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 font-mono text-xs">
                {event.raw || "화면에 원문이 포함되지 않았습니다. JSON 내보내기에서 확인하세요."}
              </pre>
            </div>
          </details>
        );
      })}
      {refs.length > 20 ? (
        <p className="text-muted-foreground text-xs">
          처음 20개 참조를 표시합니다. 전체 근거는 JSON 내보내기에서 확인하세요.
        </p>
      ) : null}
    </div>
  );
}

function EmptyResult({ title, active }: { title: string; active: boolean }) {
  return (
    <Card>
      <CardContent className="space-y-2 py-5">
        <p className="flex items-center gap-2 font-medium text-sm">
          {active ? <Spinner /> : null}
          {title}
        </p>
        <p className="text-muted-foreground text-sm">
          {active
            ? "결과가 보존되면 이 탭에 표시됩니다. 다른 탭을 확인하는 동안에도 상태는 자동 갱신됩니다."
            : "이 단계의 보존된 결과가 없습니다. 실행 상태와 기록을 확인하세요."}
        </p>
      </CardContent>
    </Card>
  );
}

export function HuntingResultView({
  run,
  activePhase,
  onPhaseChange,
  tabsRef,
  tabsId,
}: {
  run: HuntingRun;
  activePhase: HuntingPhaseId;
  onPhaseChange: (phase: HuntingPhaseId) => void;
  tabsRef: React.Ref<HTMLDivElement>;
  tabsId: string;
}) {
  const result = run.result;
  const events = React.useMemo(() => normalizedEvents(run), [run]);
  const research = result?.research ?? latestSnapshot<HuntingResult["research"]>(events, "research_completed");
  const design = result?.design ?? latestSnapshot<HuntingResult["design"]>(events, "design_completed");
  const investigation = result?.investigation;
  const verification =
    result?.verification ?? latestSnapshot<HuntingResult["verification"]>(events, "partial_verification");
  const collections = React.useMemo(() => {
    if (investigation?.collections?.length) return investigation.collections;
    return events.flatMap((event) => {
      if (event.kind !== "evidence_collection") return [];
      const collection = object(object(event.payload)?.collection);
      return collection &&
        object(collection.scope) &&
        object(collection.mapping) &&
        object(collection.stats) &&
        (Array.isArray(collection.events) || collection.events === null)
        ? [collection as unknown as InvestigationCollection]
        : [];
    });
  }, [investigation?.collections, events]);
  const sources = React.useMemo(
    () => new Map((research?.sources ?? []).map((source) => [source.id, source])),
    [research?.sources],
  );
  const { index, conflicts } = React.useMemo(() => {
    const index = new Map<string, IndexedEvidence>();
    const conflicts = new Set<string>();
    for (const collection of collections ?? []) {
      for (const event of collection.events ?? []) {
        const previous = index.get(event.ref);
        if (previous && previous.event.raw !== event.raw) conflicts.add(event.ref);
        else if (!previous) index.set(event.ref, { event, collection });
      }
    }
    return { index, conflicts };
  }, [collections]);
  const partial = [
    "insufficient_data",
    "budget_exhausted",
    "cancelled",
    "interrupted",
    "model_error",
    "failed",
  ].includes(run.status);
  const investigationSummary =
    investigation?.status === "budget_exhausted" || run.status === "budget_exhausted"
      ? "조사 한도에 도달해 일부 단계만 확인했습니다. 아래 수집 근거와 미확인 항목을 검토하세요."
      : investigation?.summary;

  return (
    <div className="space-y-4">
      <div className="space-y-2 rounded-lg border bg-card p-3">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="min-w-0 max-w-full break-words font-semibold text-sm">{run.request.term}</h2>
          <Badge aria-live="polite" variant={huntingRunActive(run.status) ? "secondary" : "outline"}>
            {huntingStatusLabel(run.status)}
          </Badge>
          <span className="text-muted-foreground text-xs">#{run.id}</span>
        </div>
        <p className="break-all text-muted-foreground text-xs">
          {run.request.scope.target}
          {run.request.scope.path_prefix} · {new Date(run.request.scope.start).toLocaleString()} →{" "}
          {new Date(run.request.scope.end).toLocaleString()}
        </p>
        <details className="text-muted-foreground text-xs">
          <summary className="cursor-pointer">실행 범위·연결 정보</summary>
          <p className="mt-2 break-all">
            연결 #{run.request.source_id} v{run.request.expected_source_revision} · 로그 유형:{" "}
            {run.request.sourcetypes?.join(", ") || "기록 없음"} · 생성 {new Date(run.created_at).toLocaleString()}
          </p>
          <p className="mt-2">이 실행의 결과는 공격 성공이나 침해 확정 판정이 아닙니다.</p>
        </details>
        {run.error || result?.error ? (
          <Alert variant="destructive">
            <AlertDescription className="whitespace-pre-wrap break-words">
              {run.error || result?.error}
            </AlertDescription>
          </Alert>
        ) : null}
        {partial ? (
          <p className="text-amber-700 text-xs dark:text-amber-300">
            미확인 항목이 남아 있습니다. 보존된 부분 결과를 침해 없음으로 판정하지 않습니다.
          </p>
        ) : null}
      </div>
      <div ref={tabsRef} id={tabsId} className="scroll-mt-52 md:scroll-mt-60">
        <Tabs
          value={activePhase}
          onValueChange={(value) => {
            const phase = HUNTING_PHASES.find((item) => item.id === value);
            if (phase) onPhaseChange(phase.id);
          }}
          className="gap-4"
        >
          <TabsList aria-label="헌팅 결과 단계" className="grid h-10 w-full grid-cols-4">
            {HUNTING_PHASES.map((phase) => (
              <TabsTrigger
                key={phase.id}
                value={phase.id}
                data-hunting-phase={phase.id}
                className="min-w-0 px-1 text-[11px] sm:text-sm"
              >
                {phase.label}
              </TabsTrigger>
            ))}
          </TabsList>
          <TabsContent value="research" className="space-y-4">
            {research && (research.summary || research.sources?.length || research.warnings?.length) ? (
              <Card>
                <CardHeader>
                  <CardTitle>자료 조사와 출처</CardTitle>
                  <CardDescription>
                    가져온 공개 자료를 근거로 정리한 내용입니다. 실제 악용·재현을 확인한 결과와 구분하세요.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {research.summary ? (
                    <p className="whitespace-pre-wrap text-sm leading-relaxed">{research.summary}</p>
                  ) : null}
                  {research.cves?.length ? (
                    <div className="flex flex-wrap gap-2">
                      {research.cves.map((cve) => (
                        <Badge key={cve} variant="outline">
                          {cve}
                        </Badge>
                      ))}
                    </div>
                  ) : null}
                  {research.claims?.length ? (
                    <div className="space-y-3">
                      {research.claims.map((claim, index) => (
                        <div key={`${index}-${claim.text}`} className="space-y-2 rounded-lg border p-3">
                          <p className="whitespace-pre-wrap text-sm">{claim.text}</p>
                          <SourceLinks ids={claim.source_ids} sources={sources} />
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <StringList values={research.warnings} label="자료 조사 한계" />
                  {research.sources?.map((source) => (
                    <details key={source.id} className="min-w-0 rounded-lg border p-4">
                      <summary className="cursor-pointer break-words font-medium text-sm">
                        {source.title || source.url}
                      </summary>
                      <div className="mt-3 space-y-3">
                        <SourceLinks ids={[source.id]} sources={sources} />
                        <p className="text-muted-foreground text-xs">
                          조회 {new Date(source.fetched_at).toLocaleString()} · 출처 {source.id}
                        </p>
                        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 text-xs">
                          {source.excerpt}
                        </pre>
                        <p className="break-all font-mono text-muted-foreground text-xs">
                          발췌문 SHA-256: {source.sha256}
                        </p>
                        <p className="text-muted-foreground text-xs">
                          해시는 보존한 발췌문 바이트의 무결성 확인용이며 자료 내용의 사실성을 보증하지 않습니다.
                        </p>
                      </div>
                    </details>
                  ))}
                </CardContent>
              </Card>
            ) : (
              <EmptyResult title="리서치 결과 대기" active={huntingRunActive(run.status)} />
            )}
          </TabsContent>
          <TabsContent value="design" className="space-y-4">
            {design?.stages?.length ? (
              <Card>
                <CardHeader>
                  <CardTitle>공격 가설·탐지 시나리오</CardTitle>
                  <CardDescription>{design.title}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {design.summary ? (
                    <p className="whitespace-pre-wrap text-sm leading-relaxed">{design.summary}</p>
                  ) : null}
                  <p className="text-muted-foreground text-xs">
                    공격 단계는 조사 가설입니다. 실제 관측과 원문 근거는 근거 판정 탭에서 확인하세요.
                  </p>
                  {design.stages.map((stage, stageIndex) => {
                    return (
                      <details key={stage.id} open={stageIndex === 0} className="rounded-lg border p-4">
                        <summary className="flex cursor-pointer flex-wrap items-center gap-2">
                          <h3 className="font-medium text-sm">
                            구간 {stageIndex + 1} · {stage.detection_question}
                          </h3>
                          <Badge variant="outline">가설</Badge>
                        </summary>
                        <div className="mt-4 space-y-4">
                          <div className="space-y-1.5">
                            <p className="font-medium text-xs">공격 가설</p>
                            <p className="whitespace-pre-wrap text-sm leading-relaxed">{stage.attack_description}</p>
                          </div>
                          <SourceLinks ids={stage.source_ids} sources={sources} />
                          <div className="grid gap-4 md:grid-cols-2">
                            <StringList values={stage.required_fields} label="필요한 필드" />
                            <StringList values={stage.benign_alternatives} label="검토할 정상 대안" />
                          </div>
                          {stage.success_criteria ? (
                            <div className="space-y-1">
                              <p className="font-medium text-sm">탐지 질문의 확인 기준</p>
                              <p className="whitespace-pre-wrap text-muted-foreground text-sm">
                                {stage.success_criteria}
                              </p>
                            </div>
                          ) : null}
                          {stage.depends_on?.length ? (
                            <p className="text-muted-foreground text-xs">선행 구간: {stage.depends_on.join(", ")}</p>
                          ) : null}
                        </div>
                      </details>
                    );
                  })}
                </CardContent>
              </Card>
            ) : (
              <EmptyResult title="시나리오 결과 대기" active={huntingRunActive(run.status)} />
            )}
          </TabsContent>
          <TabsContent value="investigation" className="space-y-4">
            {investigationSummary || collections.length || investigation?.observations?.length ? (
              <Card>
                <CardHeader>
                  <CardTitle>Splunk 헌팅과 수집 상태</CardTitle>
                  <CardDescription>
                    검색 결과·실제 원문·수집 범위를 확인하세요. 조회 완료가 센서 배치와 로그 보존 범위까지 보장하지는
                    않습니다.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {investigationSummary ? (
                    <p className="whitespace-pre-wrap text-sm leading-relaxed">{investigationSummary}</p>
                  ) : null}
                  {investigation?.usage ? (
                    <p className="text-muted-foreground text-xs">
                      모델 호출 {investigation.usage.model_calls}회 · 조회 {investigation.usage.queries}회 (원격{" "}
                      {investigation.usage.remote_queries}회) · 입력 {investigation.usage.input_tokens} / 출력{" "}
                      {investigation.usage.output_tokens} 토큰
                    </p>
                  ) : null}
                  <StringList values={investigation?.gaps} label="자료 공백" />
                  <StringList values={investigation?.next_steps} label="추가 조사" />
                  {collections?.map((collection, collectionIndex) => (
                    <details
                      key={`${collectionIndex}-${collection.collected_at}`}
                      className="min-w-0 rounded-lg border p-4"
                    >
                      <summary className="cursor-pointer text-sm">
                        수집 {collectionIndex + 1} · {collection.stats.selected}건 ·{" "}
                        {collection.complete ? "반환·파싱 범위 확인" : "수집 결과에 공백 있음"}
                      </summary>
                      <div className="mt-3 space-y-3">
                        <p className="break-all text-xs">
                          {collection.scope.target}
                          {collection.scope.path_prefix} · {new Date(collection.scope.start).toLocaleString()} →{" "}
                          {new Date(collection.scope.end).toLocaleString()}
                        </p>
                        <p className="text-muted-foreground text-xs">
                          ARTEX 표식 {collection.stats.known_artex}건 · 무효 {collection.stats.invalid_events}건 · 절단{" "}
                          {collection.stats.truncated}건 · 대상 필드 누락 {collection.stats.missing_target}건
                        </p>
                        <StringList values={collection.warnings} label="수집 경고" />
                        {collection.query ? (
                          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 text-xs">
                            {collection.query}
                          </pre>
                        ) : null}
                        <p className="text-muted-foreground text-xs">
                          매핑: 대상 {collection.mapping.target} · 시각 {collection.mapping.timestamp} · 경로{" "}
                          {collection.mapping.path || "미지정"}
                        </p>
                        <p className="text-muted-foreground text-xs">
                          전체 원문과 수집 메타데이터는 JSON 내보내기에서 확인할 수 있습니다.
                        </p>
                      </div>
                    </details>
                  ))}
                  {investigation?.observations?.length ? (
                    <details className="rounded-lg border p-4">
                      <summary className="cursor-pointer font-medium text-sm">AI 조사 관측 기록</summary>
                      <div className="mt-3 space-y-4">
                        {investigation.observations.map((observation, indexNumber) => (
                          <div
                            key={`${indexNumber}-${observation.stage_id}`}
                            className="space-y-3 rounded-md bg-muted/40 p-3"
                          >
                            <div className="flex flex-wrap gap-2">
                              <Badge variant="outline">{ASSESSMENT_LABELS[observation.kind] || observation.kind}</Badge>
                              <span className="text-muted-foreground text-xs">구간 {observation.stage_id}</span>
                            </div>
                            <p className="whitespace-pre-wrap text-sm">{observation.summary}</p>
                            <StringList values={observation.alternatives} label="다른 해석" />
                            <EvidenceRefs
                              refs={observation.evidence_refs}
                              index={index}
                              conflicts={conflicts}
                              label="관측이 인용한 근거"
                            />
                          </div>
                        ))}
                      </div>
                    </details>
                  ) : null}
                </CardContent>
              </Card>
            ) : (
              <EmptyResult title="Splunk 헌팅 결과 대기" active={huntingRunActive(run.status)} />
            )}
          </TabsContent>
          <TabsContent value="verification" className="space-y-4">
            {verification && (verification.summary || verification.warnings?.length) ? (
              <Card>
                <CardHeader>
                  <CardTitle>근거 판정과 남은 확인</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="whitespace-pre-wrap text-sm leading-relaxed">{verification.summary}</p>
                  <StringList values={verification.warnings} label="검증 한계" />
                  <p className="text-muted-foreground text-xs leading-relaxed">
                    근거 참조의 유효성과 원문 관측은 주장 전체의 의미가 검증됐다는 뜻이 아닙니다. 악용 성공과 실제
                    영향은 별도의 직접 근거가 필요합니다.
                  </p>
                </CardContent>
              </Card>
            ) : (
              <EmptyResult title="근거 판정 결과 대기" active={huntingRunActive(run.status)} />
            )}
            {verification?.stages?.map((assessment, assessmentIndex) => {
              const stage = design?.stages?.find((item) => item.id === assessment.stage_id);
              return (
                <details
                  key={assessment.stage_id}
                  open={assessmentIndex === 0}
                  className="rounded-lg border bg-card p-4"
                >
                  <summary className="flex cursor-pointer flex-wrap items-center gap-2 font-medium text-sm">
                    <span>{stage?.detection_question || assessment.stage_id}</span>
                    <Badge variant={assessment.status === "insufficient_data" ? "secondary" : "outline"}>
                      {ASSESSMENT_LABELS[assessment.status] || assessment.status}
                    </Badge>
                  </summary>
                  <div className="mt-4 space-y-4">
                    <p className="whitespace-pre-wrap text-sm leading-relaxed">{assessment.summary}</p>
                    <StringList values={assessment.reasons} label="판단 근거와 한계" />
                    <StringList values={assessment.missing_fields} label="부족한 필드" />
                    <StringList values={assessment.alternatives} label="정상 대안·다른 해석" />
                    <EvidenceRefs
                      refs={assessment.evidence_refs}
                      index={index}
                      conflicts={conflicts}
                      label="연결한 원문 근거"
                    />
                    <EvidenceRefs
                      refs={assessment.known_verification_refs}
                      index={index}
                      conflicts={conflicts}
                      label="분리한 ARTEX 검증 근거"
                    />
                    <StringList values={assessment.next_steps} label="다음 확인" />
                    {assessment.rejected_observations > 0 ? (
                      <p className="text-muted-foreground text-xs">
                        근거 검증을 통과하지 못한 관측 {assessment.rejected_observations}건을 제외했습니다.
                      </p>
                    ) : null}
                  </div>
                </details>
              );
            })}
          </TabsContent>
        </Tabs>
      </div>
      <details className="rounded-lg border p-4">
        <summary className="cursor-pointer font-medium text-sm">실행 기록 · {events.length}건</summary>
        <div className="mt-4 max-h-80 overflow-auto">
          {events.length ? (
            <ol className="space-y-3">
              {events.map((event, index) => (
                <li key={`${event.sequence}-${index}`} className="space-y-1 border-sky-500/30 border-l-2 pl-3">
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge variant="outline">{STAGE_LABELS[event.stage] || event.stage || event.kind}</Badge>
                    <span className="text-muted-foreground">{new Date(event.at).toLocaleString()}</span>
                  </div>
                  <p className="whitespace-pre-wrap break-words text-sm">{event.summary}</p>
                  {event.detail ? (
                    <details className="text-xs">
                      <summary className="cursor-pointer text-muted-foreground">상세 기록</summary>
                      <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3">
                        {event.detail}
                      </pre>
                    </details>
                  ) : null}
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-muted-foreground text-sm">
              {huntingRunActive(run.status) ? "실행 기록을 기다리고 있습니다." : "보존된 실행 기록이 없습니다."}
            </p>
          )}
        </div>
      </details>
    </div>
  );
}
