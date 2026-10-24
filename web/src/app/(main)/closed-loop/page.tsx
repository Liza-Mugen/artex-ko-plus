"use client";

import * as React from "react";

import Link from "next/link";

import { DownloadIcon, FlaskConicalIcon, RefreshCwIcon, Repeat2Icon } from "lucide-react";
import { useTranslations } from "next-intl";

import { ClosedLoopLivePanel } from "@/components/closed-loop-live-panel";
import { ClosedLoopRangePanel } from "@/components/closed-loop-range-panel";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  type ClosedLoopIteration,
  type ClosedLoopSummary,
  closedloopApi,
  type LoopInput,
  type LoopResult,
  type LoopRule,
  type LoopSuggestion,
} from "@/lib/closedloop-api";

const baselineExample: LoopRule = {
  name: "Private legacy route",
  any: [{ all: [{ field: "path", op: "equals", value: "/private/legacy.csv", case_sensitive: true }] }],
};
const candidateExample: LoopRule = {
  name: "Anonymous private route",
  any: [
    {
      all: [
        { field: "path", op: "contains", value: "/private/", case_sensitive: true },
        { field: "auth_state", op: "equals", value: "anonymous", case_sensitive: true },
      ],
    },
  ],
};
const tuningExample = [
  {
    event_id: "synthetic-t1",
    label: "attack",
    fields: { path: "/private/legacy.csv", auth_state: "anonymous", method: "GET" },
  },
  {
    event_id: "synthetic-t2",
    label: "attack",
    fields: { path: "/private/export.csv", auth_state: "anonymous", method: "GET" },
  },
  {
    event_id: "synthetic-t3",
    label: "benign",
    fields: { path: "/private/legacy.csv", auth_state: "authenticated", method: "GET" },
  },
  { event_id: "synthetic-t4", label: "benign", fields: { path: "/docs/help", auth_state: "anonymous", method: "GET" } },
]
  .map((event) => JSON.stringify(event))
  .join("\n");
const evaluationExample = [
  {
    event_id: "synthetic-e1",
    label: "attack",
    fields: { path: "/private/legacy.csv", auth_state: "anonymous", method: "HEAD" },
  },
  {
    event_id: "synthetic-e2",
    label: "attack",
    fields: { path: "/private/report.csv", auth_state: "anonymous", method: "GET" },
  },
  {
    event_id: "synthetic-e3",
    label: "benign",
    fields: { path: "/private/legacy.csv", auth_state: "authenticated", method: "HEAD" },
  },
  {
    event_id: "synthetic-e4",
    label: "benign",
    fields: { path: "/docs/start", auth_state: "anonymous", method: "GET" },
  },
]
  .map((event) => JSON.stringify(event))
  .join("\n");
const metricKeys = [
  "tp",
  "fp",
  "tn",
  "fn",
  "unknown_attack",
  "unknown_benign",
  "precision",
  "recall",
  "false_positive_rate",
  "accuracy",
  "mttd_seconds",
] as const;
const rateKeys = new Set(["precision", "recall", "false_positive_rate", "accuracy"]);
const json = (value: unknown) => JSON.stringify(value, null, 2);

function OfflineClosedLoopPanel() {
  const t = useTranslations("ClosedLoop");
  const [scenario, setScenario] = React.useState("");
  const [findingId, setFindingId] = React.useState("");
  const [caseId, setCaseId] = React.useState("");
  const [baselineText, setBaselineText] = React.useState(json(baselineExample));
  const [candidateText, setCandidateText] = React.useState(json(candidateExample));
  const [tuningLogs, setTuningLogs] = React.useState("");
  const [evaluationLogs, setEvaluationLogs] = React.useState("");
  const [notes, setNotes] = React.useState("");
  const [confirmedTimes, setConfirmedTimes] = React.useState(false);
  const [synthetic, setSynthetic] = React.useState(false);
  const [suggestion, setSuggestion] = React.useState<LoopSuggestion | null>(null);
  const [preview, setPreview] = React.useState<{ key: string; result: LoopResult } | null>(null);
  const [records, setRecords] = React.useState<ClosedLoopSummary[]>([]);
  const [selected, setSelected] = React.useState<ClosedLoopIteration | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [message, setMessage] = React.useState("");
  const key = JSON.stringify({
    scenario,
    findingId,
    caseId,
    baselineText,
    candidateText,
    tuningLogs,
    evaluationLogs,
    notes,
    confirmedTimes,
  });
  const currentPreview = preview?.key === key ? preview.result : null;

  const refresh = React.useCallback(async () => {
    const result = await closedloopApi.list();
    setRecords(result.iterations);
  }, []);
  React.useEffect(() => {
    refresh().catch((e: Error) => setError(e.message));
  }, [refresh]);

  function input(): LoopInput {
    if ((findingId && !/^[1-9]\d*$/.test(findingId)) || (caseId && !/^[1-9]\d*$/.test(caseId)))
      throw new Error(t("invalidId"));
    return {
      scenario,
      ...(findingId ? { finding_id: findingId } : {}),
      ...(caseId ? { case_id: caseId } : {}),
      baseline_rule: JSON.parse(baselineText) as LoopRule,
      candidate_rule: JSON.parse(candidateText) as LoopRule,
      tuning_logs: tuningLogs,
      evaluation_logs: evaluationLogs,
      notes,
      timestamp_provenance_confirmed: confirmedTimes,
    };
  }
  async function action(run: () => Promise<void>) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await run();
    } catch (e) {
      setError(e instanceof Error ? e.message : t("requestFailed"));
    } finally {
      setBusy(false);
    }
  }
  async function upload(event: React.ChangeEvent<HTMLInputElement>, kind: "tuning" | "evaluation") {
    const file = event.target.files?.[0];
    if (!file) return;
    await action(async () => {
      if (file.size > 2 * 1024 * 1024) throw new Error(t("tooLarge"));
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer());
      } catch {
        throw new Error(t("invalidEncoding"));
      }
      if (kind === "tuning") setTuningLogs(text);
      else setEvaluationLogs(text);
      setSynthetic(false);
      setSuggestion(null);
      setMessage(t("uploaded", { name: file.name }));
    });
    event.target.value = "";
  }
  function download(value: unknown, name: string) {
    const url = URL.createObjectURL(new Blob([json(value)], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    URL.revokeObjectURL(url);
  }
  function metric(value: number | null, name: string) {
    if (value === null) return t("unknown");
    if (rateKeys.has(name)) return `${(value * 100).toFixed(1)}%`;
    if (name === "mttd_seconds") return t("seconds", { value: value.toFixed(2) });
    return value.toLocaleString();
  }
  function comparison(result: LoopResult) {
    const data = result.evaluation_comparison;
    return (
      <div className="space-y-4">
        <Alert>
          <AlertDescription>{t("resultScope")}</AlertDescription>
        </Alert>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("metric")}</TableHead>
              <TableHead>{t("baseline")}</TableHead>
              <TableHead>{t("candidate")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {metricKeys.map((name) => (
              <TableRow key={name}>
                <TableCell>{t(`metrics.${name}`)}</TableCell>
                <TableCell>{metric(data.baseline[name], name)}</TableCell>
                <TableCell>{metric(data.candidate[name], name)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <p className="text-muted-foreground text-xs">{t("metricLimits")}</p>
        <div className="grid gap-3 md:grid-cols-2">
          {(["tuning", "evaluation"] as const).map((kind) => (
            <div key={kind} className="space-y-2 rounded-md border p-3 text-sm">
              <p className="font-medium">{t(kind)}</p>
              <p>
                {t("datasetCounts", {
                  total: result[kind].events,
                  attack: result[kind].attacks,
                  benign: result[kind].benign,
                })}
              </p>
              <code className="block break-all text-xs">SHA-256: {result[kind].sha256}</code>
            </div>
          ))}
        </div>
        <div className="space-y-2">
          <h3 className="font-medium">{t("priorities")}</h3>
          <p className="text-muted-foreground text-sm">{t("priorityDescription")}</p>
          {result.next_validation_priorities.length ? (
            result.next_validation_priorities.map((item) => (
              <div key={item.kind} className="rounded-md border p-3 text-sm">
                <p className="font-medium">{t(`priority.${item.kind}`)}</p>
                <p className="mt-1 break-all">{item.event_ids.join(", ")}</p>
              </div>
            ))
          ) : (
            <p className="text-sm">{t("noPriorities")}</p>
          )}
        </div>
        <div className="space-y-1 text-muted-foreground text-xs">
          {result.warnings.map((warning) => (
            <p key={warning}>{t(`warnings.${warning}`)}</p>
          ))}
        </div>
        <details className="rounded-md border p-3">
          <summary className="cursor-pointer font-medium text-sm">{t("evidence")}</summary>
          <div className="mt-3 max-h-80 overflow-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("eventId")}</TableHead>
                  <TableHead>{t("label")}</TableHead>
                  <TableHead>{t("baseline")}</TableHead>
                  <TableHead>{t("candidate")}</TableHead>
                  <TableHead>{t("missingFields")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.evidence.map((event) => (
                  <TableRow key={event.event_id}>
                    <TableCell>{event.event_id}</TableCell>
                    <TableCell>{t(`labels.${event.label}`)}</TableCell>
                    <TableCell>{t(`outcome.${event.baseline}`)}</TableCell>
                    <TableCell>{t(`outcome.${event.candidate}`)}</TableCell>
                    <TableCell>{event.missing_fields.join(", ") || "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </details>
        <details className="rounded-md border p-3">
          <summary className="cursor-pointer font-medium text-sm">{t("tuningResults")}</summary>
          <pre className="mt-3 overflow-auto text-xs">{json(result.tuning_comparison)}</pre>
        </details>
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3 lg:px-6">
        <div className="flex items-center gap-3">
          <SidebarTrigger className="-ml-1" />
          <Repeat2Icon className="size-5 text-violet-500" />
          <h1 className="font-semibold">{t("title")}</h1>
          <Badge variant="outline">{t("offlineBadge")}</Badge>
        </div>
        <Button variant="outline" size="sm" disabled={busy} onClick={() => action(refresh)}>
          <RefreshCwIcon />
          {t("refresh")}
        </Button>
      </header>
      <div className="flex flex-col gap-6 p-4 lg:p-6">
        <div>
          <h2 className="font-semibold text-xl">{t("heading")}</h2>
          <p className="mt-2 max-w-4xl text-muted-foreground text-sm leading-relaxed">{t("description")}</p>
        </div>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {message ? (
          <Alert>
            <AlertDescription>{message}</AlertDescription>
          </Alert>
        ) : null}
        <Card>
          <CardHeader>
            <CardTitle>{t("prepare")}</CardTitle>
            <CardDescription>{t("prepareDescription")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="space-y-2 lg:col-span-3">
                <Label htmlFor="loop-scenario">{t("scenario")}</Label>
                <Input
                  id="loop-scenario"
                  maxLength={200}
                  value={scenario}
                  disabled={busy}
                  onChange={(e) => setScenario(e.target.value)}
                  placeholder={t("scenarioPlaceholder")}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="loop-finding">{t("findingId")}</Label>
                <Input
                  id="loop-finding"
                  inputMode="numeric"
                  value={findingId}
                  disabled={busy}
                  onChange={(e) => setFindingId(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="loop-case">{t("caseId")}</Label>
                <Input
                  id="loop-case"
                  inputMode="numeric"
                  value={caseId}
                  disabled={busy}
                  onChange={(e) => setCaseId(e.target.value)}
                />
              </div>
              <div className="flex items-end">
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => {
                    setScenario(t("syntheticScenario"));
                    setNotes("");
                    setTuningLogs(tuningExample);
                    setEvaluationLogs(evaluationExample);
                    setBaselineText(json(baselineExample));
                    setCandidateText(json(candidateExample));
                    setConfirmedTimes(false);
                    setSynthetic(true);
                    setSuggestion(null);
                    setPreview(null);
                    setFindingId("");
                    setCaseId("");
                    setMessage(t("syntheticNotice"));
                  }}
                >
                  <FlaskConicalIcon />
                  {t("loadExample")}
                </Button>
              </div>
            </div>
            <p className="text-muted-foreground text-xs">{t("referenceLimits")}</p>
            {synthetic ? (
              <Alert>
                <AlertDescription>{t("syntheticNotice")}</AlertDescription>
              </Alert>
            ) : null}
            <div className="grid gap-5 xl:grid-cols-2">
              {(["tuning", "evaluation"] as const).map((kind) => (
                <div key={kind} className="space-y-3">
                  <Label htmlFor={`loop-${kind}`}>{t(kind)}</Label>
                  <p className="text-muted-foreground text-sm">{t(`${kind}Description`)}</p>
                  <Input
                    aria-label={t(`${kind}Upload`)}
                    type="file"
                    accept=".jsonl,.ndjson,.json,.txt"
                    disabled={busy}
                    onChange={(e) => upload(e, kind)}
                  />
                  <Textarea
                    id={`loop-${kind}`}
                    className="min-h-44 font-mono text-xs"
                    value={kind === "tuning" ? tuningLogs : evaluationLogs}
                    disabled={busy}
                    onChange={(e) => {
                      if (kind === "tuning") setTuningLogs(e.target.value);
                      else setEvaluationLogs(e.target.value);
                      setSynthetic(false);
                      setSuggestion(null);
                    }}
                    placeholder={t("jsonlPlaceholder")}
                  />
                </div>
              ))}
            </div>
            <details className="rounded-md border p-3">
              <summary className="cursor-pointer font-medium text-sm">{t("format")}</summary>
              <p className="mt-3 text-muted-foreground text-sm">{t("formatDescription")}</p>
              <pre className="mt-3 overflow-auto text-xs">
                {
                  '{"event_id":"unique-id","label":"attack","fields":{"path":"/private/export.csv","auth_state":"anonymous"}}'
                }
              </pre>
              <p className="mt-3 text-muted-foreground text-sm">{t("timestampFormat")}</p>
            </details>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{t("improve")}</CardTitle>
            <CardDescription>{t("ruleDescription")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-5 xl:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="loop-baseline">{t("baselineRule")}</Label>
                <Textarea
                  id="loop-baseline"
                  className="min-h-64 font-mono text-xs"
                  value={baselineText}
                  disabled={busy}
                  onChange={(e) => {
                    setBaselineText(e.target.value);
                    setSuggestion(null);
                  }}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="loop-candidate">{t("candidateRule")}</Label>
                <Textarea
                  id="loop-candidate"
                  className="min-h-64 font-mono text-xs"
                  value={candidateText}
                  disabled={busy}
                  onChange={(e) => {
                    setCandidateText(e.target.value);
                    setSuggestion(null);
                  }}
                />
              </div>
            </div>
            <Button
              variant="outline"
              disabled={busy || !tuningLogs.trim()}
              onClick={() =>
                action(async () => {
                  const proposal = await closedloopApi.suggest(tuningLogs, JSON.parse(baselineText) as LoopRule);
                  setCandidateText(json(proposal.candidate_rule));
                  setSuggestion(proposal);
                  setPreview(null);
                })
              }
            >
              {t("suggest")}
            </Button>
            <p className="text-muted-foreground text-xs">{t("suggestDescription")}</p>
            {suggestion ? (
              <div className="space-y-2 rounded-md border p-3 text-sm">
                <p>{t("suggestionCount", { count: suggestion.added_conditions.length })}</p>
                {suggestion.warnings.map((warning) => (
                  <p key={warning} className="text-muted-foreground">
                    {t(`warnings.${warning}`)}
                  </p>
                ))}
                {suggestion.unresolved_event_ids.length ? (
                  <p>
                    {t("unresolved")}: {suggestion.unresolved_event_ids.join(", ")}
                  </p>
                ) : null}
              </div>
            ) : null}
            <div className="space-y-2">
              <Label htmlFor="loop-notes">{t("notes")}</Label>
              <Textarea
                id="loop-notes"
                maxLength={4000}
                value={notes}
                disabled={busy}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="loop-timing"
                checked={confirmedTimes}
                disabled={busy}
                onCheckedChange={(value) => setConfirmedTimes(value === true)}
              />
              <Label htmlFor="loop-timing" className="text-sm leading-relaxed">
                {t("confirmedTimes")}
              </Label>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                disabled={busy || !scenario.trim() || !tuningLogs.trim() || !evaluationLogs.trim()}
                onClick={() =>
                  action(async () => {
                    const result = await closedloopApi.evaluate(input());
                    setPreview({ key, result });
                    setSelected(null);
                  })
                }
              >
                {t("evaluate")}
              </Button>
              <Button
                variant="outline"
                disabled={busy || !currentPreview}
                onClick={() =>
                  action(async () => {
                    const saved = await closedloopApi.save(input());
                    setSelected(saved);
                    await refresh();
                    setMessage(t("saved", { id: saved.id }));
                  })
                }
              >
                {t("save")}
              </Button>
            </div>
            {preview && !currentPreview ? <p className="text-amber-600 text-sm">{t("previewStale")}</p> : null}
          </CardContent>
        </Card>
        {currentPreview ? (
          <Card>
            <CardHeader>
              <CardTitle>{t("comparison")}</CardTitle>
              <CardDescription>{t("heldOutSameData")}</CardDescription>
            </CardHeader>
            <CardContent>{comparison(currentPreview)}</CardContent>
          </Card>
        ) : null}
        <Card>
          <CardHeader>
            <CardTitle>{t("history")}</CardTitle>
            <CardDescription>{t("historyDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            {records.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("scenario")}</TableHead>
                    <TableHead>{t("createdAt")}</TableHead>
                    <TableHead>{t("recallChange")}</TableHead>
                    <TableHead>{t("fprChange")}</TableHead>
                    <TableHead>{t("actions")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {records.map((record) => (
                    <TableRow key={record.id}>
                      <TableCell>
                        {record.scenario}
                        <p className="text-muted-foreground text-xs">#{record.id}</p>
                      </TableCell>
                      <TableCell>{new Date(record.created_at).toLocaleString()}</TableCell>
                      <TableCell>
                        {metric(record.comparison.baseline.recall, "recall")} →{" "}
                        {metric(record.comparison.candidate.recall, "recall")}
                      </TableCell>
                      <TableCell>
                        {metric(record.comparison.baseline.false_positive_rate, "false_positive_rate")} →{" "}
                        {metric(record.comparison.candidate.false_positive_rate, "false_positive_rate")}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={busy}
                            onClick={() => action(async () => setSelected(await closedloopApi.get(record.id)))}
                          >
                            {t("view")}
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={busy}
                            onClick={() =>
                              action(async () =>
                                download(await closedloopApi.export(record.id), `closed-loop-${record.id}.json`),
                              )
                            }
                          >
                            <DownloadIcon />
                            {t("export")}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-muted-foreground text-sm">{t("emptyHistory")}</p>
            )}
          </CardContent>
        </Card>
        {selected ? (
          <Card>
            <CardHeader>
              <CardTitle>
                {t("savedDetail", { id: selected.id })}: {selected.input.scenario}
              </CardTitle>
              <CardDescription>{t("immutableSnapshot")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                {selected.input.finding_id ? (
                  <Button variant="outline" size="sm" asChild>
                    <Link href={`/function/findings/detail?id=${encodeURIComponent(selected.input.finding_id)}`}>
                      {t("linkedFinding", { id: selected.input.finding_id })}
                    </Link>
                  </Button>
                ) : null}
                {selected.input.case_id ? (
                  <Badge variant="outline">{t("linkedCase", { id: selected.input.case_id })}</Badge>
                ) : null}
              </div>
              {selected.input.notes ? <p className="whitespace-pre-wrap text-sm">{selected.input.notes}</p> : null}
              {comparison(selected.result)}
              <details className="rounded-md border p-3">
                <summary className="cursor-pointer text-sm">{t("savedRules")}</summary>
                <pre className="mt-3 overflow-auto text-xs">
                  {json({ baseline_rule: selected.input.baseline_rule, candidate_rule: selected.input.candidate_rule })}
                </pre>
              </details>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </div>
  );
}

export default function ClosedLoopPage() {
  const t = useTranslations("LiveLoop");
  const tr = useTranslations("RangeLoop");
  const [tab, setTab] = React.useState("live");
  React.useEffect(() => {
    const requested = new URLSearchParams(window.location.search).get("tab");
    if (requested === "range" || requested === "offline") setTab(requested);
  }, []);
  const changeTab = (value: string) => {
    setTab(value);
    const url = new URL(window.location.href);
    if (value === "live") url.searchParams.delete("tab");
    else url.searchParams.set("tab", value);
    window.history.replaceState(window.history.state, "", url);
  };
  return (
    <Tabs value={tab} onValueChange={changeTab} className="flex flex-1 flex-col gap-0">
      <div className="border-b px-4 py-3 lg:px-6">
        <TabsList className="h-auto flex-wrap">
          <TabsTrigger value="live">{t("liveTab")}</TabsTrigger>
          <TabsTrigger value="range">{tr("tab")}</TabsTrigger>
          <TabsTrigger value="offline">{t("offlineTab")}</TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="live" className="mt-0">
        <ClosedLoopLivePanel />
      </TabsContent>
      <TabsContent value="range" className="mt-0">
        <ClosedLoopRangePanel />
      </TabsContent>
      <TabsContent value="offline" className="mt-0">
        <OfflineClosedLoopPanel />
      </TabsContent>
    </Tabs>
  );
}
