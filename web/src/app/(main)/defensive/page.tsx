"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

import {
  ArrowUpRightIcon,
  FileSearchIcon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  Trash2Icon,
  UploadIcon,
  XIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { FindingInvestigationAgentPanel } from "@/components/finding-investigation-agent-panel";
import { InvestigationEvidenceNotice, InvestigationResult } from "@/components/finding-investigation-panel";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { HttpError } from "@/lib/api";
import {
  type DefensiveCase,
  type DefensiveCaseInput,
  type DefensiveCaseSummary,
  defensiveAgentApi,
  defensiveApi,
} from "@/lib/defensive-api";
import {
  DEFAULT_INVESTIGATION_MAPPING,
  type InvestigationMapping,
  type InvestigationPreview,
} from "@/lib/investigation-api";
import { investigationMappingForSource } from "@/lib/investigation-mapping";
import { downloadSecurityJSON, type SecuritySource, securityApi, securitySourceSourcetypes } from "@/lib/security-api";

const MAX_BYTES = 8 * 1024 * 1024;
const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50";
type LoadedFile = { name: string; content: string; bytes: number };
function localTime(time: number) {
  const date = new Date(time);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
}

function DefensivePageContent() {
  const t = useTranslations("investigation");
  const ta = useTranslations("Aegis");
  const router = useRouter();
  const params = useSearchParams();
  const queryCase = params.get("case");
  const fieldId = React.useId();
  const [cases, setCases] = React.useState<DefensiveCaseSummary[]>([]);
  const [total, setTotal] = React.useState<number | null>(null);
  const [truncated, setTruncated] = React.useState(false);
  const [sources, setSources] = React.useState<SecuritySource[]>([]);
  const [sourceError, setSourceError] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState<"load" | "read" | "preview" | "create" | "record" | null>("load");
  const [newMode, setNewMode] = React.useState(params.get("new") === "1");
  const [sourceKind, setSourceKind] = React.useState<"file" | "splunk">("file");
  const [sourceId, setSourceId] = React.useState("");
  const [sourcetypes, setSourcetypes] = React.useState("");
  const [title, setTitle] = React.useState("");
  const [question, setQuestion] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [pathPrefix, setPathPrefix] = React.useState("");
  const [start, setStart] = React.useState(() => localTime(Date.now() - 86400000));
  const [end, setEnd] = React.useState(() => localTime(Date.now()));
  const [mapping, setMapping] = React.useState<InvestigationMapping>({ ...DEFAULT_INVESTIGATION_MAPPING });
  const [fileLabel, setFileLabel] = React.useState("");
  const [files, setFiles] = React.useState<LoadedFile[]>([]);
  const [coverageConfirmed, setCoverageConfirmed] = React.useState(false);
  const [targetScopeConfirmed, setTargetScopeConfirmed] = React.useState(false);
  const [preview, setPreview] = React.useState<{ key: string; result: InvestigationPreview } | null>(null);
  const [record, setRecord] = React.useState<DefensiveCase | null>(null);
  const [caseToDelete, setCaseToDelete] = React.useState<DefensiveCaseSummary | null>(null);
  const [deletingCase, setDeletingCase] = React.useState(false);
  const [pendingEvidence, setPendingEvidence] = React.useState(false);
  const [exporting, setExporting] = React.useState(false);
  const [filter, setFilter] = React.useState("");
  const requestSeq = React.useRef(0);
  const openedQueryCase = React.useRef<string | null>(null);
  const resultRef = React.useRef<HTMLDivElement>(null);
  const selectedSource = sources.find((source) => source.id === sourceId);
  const totalBytes = files.reduce((sum, file) => sum + file.bytes, 0);
  const previewKey = JSON.stringify({
    sourceId,
    sourceRevision: selectedSource?.revision,
    sourcetypes,
    target,
    pathPrefix,
    start,
    end,
    mapping,
  });
  const validPreview = preview?.key === previewKey ? preview.result : null;

  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    setBusy("load");
    setError("");
    const results = await Promise.allSettled([defensiveApi.list(), securityApi.sources()]);
    if (seq !== requestSeq.current) return;
    if (results[0].status === "fulfilled") {
      const response = results[0].value;
      setCases(response.cases ?? []);
      setTotal(response.total);
      setTruncated(response.history_truncated ?? false);
      if (!response.cases?.length && !queryCase) setNewMode(true);
      if (queryCase && openedQueryCase.current !== queryCase) {
        try {
          const detail = await defensiveApi.get(queryCase);
          if (seq === requestSeq.current) {
            openedQueryCase.current = queryCase;
            setRecord(detail);
            setNewMode(false);
            setPendingEvidence(false);
          }
        } catch (caught) {
          if (seq === requestSeq.current) setError((caught as Error).message);
        }
      }
    } else setError((results[0].reason as Error).message);
    if (seq !== requestSeq.current) return;
    if (results[1].status === "fulfilled") {
      setSources(results[1].value.sources ?? []);
      setSourceError("");
    } else setSourceError((results[1].reason as Error).message);
    setBusy(null);
  }, [queryCase]);
  React.useEffect(() => {
    void load();
    return () => {
      requestSeq.current++;
    };
  }, [load]);

  const buildInput = (): DefensiveCaseInput | null => {
    const from = new Date(start);
    const until = new Date(end);
    if (
      !Number.isFinite(from.getTime()) ||
      !Number.isFinite(until.getTime()) ||
      until <= from ||
      from.getUTCFullYear() < 1970 ||
      until.getTime() > Date.now() ||
      until.getTime() - from.getTime() > 31 * 86400000
    ) {
      setError(t("invalidPeriod"));
      return null;
    }
    if (!target.trim()) {
      setError(t("targetRequired"));
      return null;
    }
    if (sourceKind === "splunk" && (!selectedSource?.enabled || !selectedSource.credential_set)) {
      setError(t("sourceRequired"));
      return null;
    }
    return {
      title: title.trim(),
      question: question.trim(),
      scope: {
        target: target.trim(),
        path_prefix: pathPrefix.trim(),
        start: from.toISOString(),
        end: until.toISOString(),
      },
      mapping,
      source_kind: sourceKind,
      file_label: fileLabel.trim(),
      files: sourceKind === "file" ? files.map(({ name, content }) => ({ name, content })) : [],
      source_id: sourceKind === "splunk" ? sourceId : "0",
      expected_source_revision: sourceKind === "splunk" ? (selectedSource?.revision ?? 0) : 0,
      sourcetypes:
        sourceKind === "splunk"
          ? sourcetypes
              .split(/[,\n]/)
              .map((value) => value.trim())
              .filter(Boolean)
          : [],
      coverage_confirmed: sourceKind === "file" && coverageConfirmed,
      target_scope_confirmed: sourceKind === "file" && targetScopeConfirmed,
    };
  };
  const handleError = async (caught: unknown) => {
    if (caught instanceof HttpError && caught.status === 409) {
      setPreview(null);
      await load();
      setError(ta("defensive.conflict"));
    } else setError((caught as Error).message);
  };
  const readFiles = async (chosen: FileList | null) => {
    if (!chosen?.length) return;
    const additions = Array.from(chosen);
    if (additions.reduce((sum, file) => sum + file.size, totalBytes) > MAX_BYTES) {
      setError(t("tooLarge"));
      return;
    }
    if (
      new Set([...files.map((file) => file.name), ...additions.map((file) => file.name)]).size !==
      files.length + additions.length
    ) {
      setError(t("duplicateFile"));
      return;
    }
    setBusy("read");
    setError("");
    try {
      const loaded = await Promise.all(
        additions.map(async (file) => ({
          name: file.name,
          bytes: file.size,
          content: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer()),
        })),
      );
      setFiles((current) => [...current, ...loaded]);
      setPendingEvidence(true);
      setCoverageConfirmed(false);
      setTargetScopeConfirmed(false);
    } catch {
      setError(t("fileError"));
    } finally {
      setBusy(null);
    }
  };
  const previewQuery = async () => {
    if (busy) return;
    setError("");
    const input = buildInput();
    if (!input) return;
    setBusy("preview");
    setPreview(null);
    try {
      setPreview({ key: previewKey, result: await defensiveApi.preview(input) });
    } catch (caught) {
      await handleError(caught);
    } finally {
      setBusy(null);
    }
  };
  const create = async () => {
    if (busy) return;
    setError("");
    const input = buildInput();
    if (!input) return;
    if (sourceKind === "file" && (!files.length || !fileLabel.trim())) {
      setError(t("fileRequired"));
      return;
    }
    if (sourceKind === "splunk" && !validPreview) {
      setError(t("previewRequired"));
      return;
    }
    if (validPreview && sourceKind === "splunk") input.expected_source_revision = validPreview.source_revision;
    setBusy("create");
    try {
      const saved = await defensiveApi.create(input);
      setRecord(saved);
      setPendingEvidence(false);
      setNewMode(false);
      toast.success(ta("defensive.saved"));
      try {
        const response = await defensiveApi.list();
        setCases(response.cases ?? []);
        setTotal(response.total);
        setTruncated(response.history_truncated ?? false);
      } catch {
        setError(t("historyRefreshError"));
      }
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (caught) {
      await handleError(caught);
    } finally {
      setBusy(null);
    }
  };
  const openRecord = async (id: string) => {
    const seq = ++requestSeq.current;
    setBusy("record");
    setError("");
    try {
      const next = await defensiveApi.get(id);
      if (seq !== requestSeq.current) return;
      setRecord(next);
      setNewMode(false);
      setPendingEvidence(false);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (caught) {
      if (seq === requestSeq.current) setError((caught as Error).message);
    } finally {
      if (seq === requestSeq.current) setBusy(null);
    }
  };
  const deleteCase = async () => {
    if (!caseToDelete || deletingCase || busy) return;
    const id = caseToDelete.id;
    setDeletingCase(true);
    setError("");
    try {
      await defensiveApi.delete(id);
      requestSeq.current++;
      setCases((current) => current.filter((item) => item.id !== id));
      setTotal((current) => (current === null ? null : Math.max(0, current - 1)));
      if (record?.id === id) {
        setRecord(null);
        setPendingEvidence(false);
      }
      if (queryCase === id) {
        openedQueryCase.current = id;
        router.replace("/defensive");
      }
      setCaseToDelete(null);
      toast.success(ta("defensive.deleted"));
      await load();
    } catch (caught) {
      const message =
        caught instanceof HttpError && caught.status === 409 ? ta("defensive.deleteActive") : (caught as Error).message;
      setError(message);
      toast.error(message);
    } finally {
      setDeletingCase(false);
    }
  };
  const exportRecord = async () => {
    if (!record || exporting) return;
    setExporting(true);
    try {
      downloadSecurityJSON(await defensiveApi.export(record.id), `aegisloop-case-${record.id}.json`);
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setExporting(false);
    }
  };
  const changeMode = (next: "file" | "splunk") => {
    setSourceKind(next);
    setPreview(null);
    setCoverageConfirmed(false);
    setTargetScopeConfirmed(false);
    setMapping((current) => investigationMappingForSource(current, sourceKind, next));
  };
  const visibleCases = cases.filter((item) =>
    `${item.title} ${item.summary} ${item.scope.target}`.toLowerCase().includes(filter.toLowerCase()),
  );
  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-5 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-2">
          <Badge variant="outline">Defensive</Badge>
          <h1 className="text-2xl font-semibold tracking-tight">{ta("defensive.title")}</h1>
          <p className="max-w-3xl text-sm text-muted-foreground leading-relaxed">{ta("defensive.description")}</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => void load()} disabled={!!busy}>
            <RefreshCwIcon className={busy === "load" ? "animate-spin" : ""} />
            {ta("refresh")}
          </Button>
          <Button size="sm" onClick={() => setNewMode(true)} disabled={!!busy}>
            <PlusIcon />
            {ta("defensive.newCase")}
          </Button>
        </div>
      </div>
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <div className="rounded-lg border border-sky-500/20 bg-sky-500/5 p-4">
        <p className="font-medium text-sm">{ta("defensive.flow")}</p>
        <p className="mt-1 text-xs text-muted-foreground leading-relaxed">{ta("defensive.boundary")}</p>
      </div>
      {newMode ? (
        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-3">
            <div className="space-y-1.5">
              <CardTitle className="flex items-center gap-2">
                <UploadIcon className="size-5 text-sky-500" />
                {ta("defensive.prepareTitle")}
              </CardTitle>
              <CardDescription>{ta("defensive.prepareHelp")}</CardDescription>
            </div>
            {cases.length ? (
              <Button size="icon" variant="ghost" onClick={() => setNewMode(false)} aria-label={ta("close")}>
                <XIcon />
              </Button>
            ) : null}
          </CardHeader>
          <CardContent>
            <fieldset
              disabled={!!busy}
              onChangeCapture={() => setPendingEvidence(true)}
              className="space-y-5 disabled:opacity-70"
            >
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-title`}>{t("caseTitle")}</Label>
                  <Input
                    id={`${fieldId}-title`}
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    maxLength={200}
                    placeholder={t("titlePlaceholder")}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-mode`}>{t("source")}</Label>
                  <select
                    id={`${fieldId}-mode`}
                    className={SELECT_CLASS}
                    value={sourceKind}
                    onChange={(event) => changeMode(event.target.value as "file" | "splunk")}
                  >
                    <option value="file">{t("fileSource")}</option>
                    <option value="splunk">{t("splunkSource")}</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor={`${fieldId}-question`}>{t("question")}</Label>
                <Textarea
                  id={`${fieldId}-question`}
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  maxLength={4000}
                  rows={2}
                  placeholder={t("questionPlaceholder")}
                />
                <p className="text-muted-foreground text-xs">{t("questionHelp")}</p>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-target`}>{t("target")}</Label>
                  <Input
                    id={`${fieldId}-target`}
                    value={target}
                    onChange={(event) => {
                      setTarget(event.target.value);
                      setTargetScopeConfirmed(false);
                      setCoverageConfirmed(false);
                    }}
                    placeholder={t("targetPlaceholder")}
                  />
                  <p className="text-muted-foreground text-xs">{t("targetHelp")}</p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-path`}>{t("pathPrefix")}</Label>
                  <Input
                    id={`${fieldId}-path`}
                    value={pathPrefix}
                    onChange={(event) => {
                      setPathPrefix(event.target.value);
                      setCoverageConfirmed(false);
                    }}
                    placeholder="/ftp"
                  />
                  <p className="text-muted-foreground text-xs">{t("pathHelp")}</p>
                </div>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-start`}>{t("start")}</Label>
                  <Input
                    id={`${fieldId}-start`}
                    type="datetime-local"
                    step="1"
                    value={start}
                    onChange={(event) => {
                      setStart(event.target.value);
                      setCoverageConfirmed(false);
                    }}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-end`}>{t("end")}</Label>
                  <Input
                    id={`${fieldId}-end`}
                    type="datetime-local"
                    step="1"
                    value={end}
                    onChange={(event) => {
                      setEnd(event.target.value);
                      setCoverageConfirmed(false);
                    }}
                  />
                </div>
              </div>
              <p className="text-muted-foreground text-xs">{t("timeHelp")}</p>
              {sourceKind === "file" ? (
                <div className="space-y-4 rounded-lg border p-4">
                  <div className="space-y-2">
                    <Label htmlFor={`${fieldId}-label`}>{t("fileLabel")}</Label>
                    <Input
                      id={`${fieldId}-label`}
                      value={fileLabel}
                      onChange={(event) => setFileLabel(event.target.value)}
                      maxLength={120}
                      placeholder={t("fileLabelPlaceholder")}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor={`${fieldId}-files`}>{t("files")}</Label>
                    <Input
                      id={`${fieldId}-files`}
                      type="file"
                      multiple
                      accept=".json,.jsonl,.ndjson,.csv,application/json,text/csv"
                      onChange={(event) => {
                        void readFiles(event.target.files);
                        event.target.value = "";
                      }}
                    />
                    <p className="text-muted-foreground text-xs leading-relaxed">
                      {t("fileLimits", { n: Math.ceil(totalBytes / 1024) })}
                    </p>
                  </div>
                  {files.length ? (
                    <div className="space-y-2">
                      {files.map((file) => (
                        <div
                          key={file.name}
                          className="flex items-center justify-between gap-2 rounded-md bg-muted/50 px-3 py-2"
                        >
                          <span className="min-w-0 truncate text-sm">
                            {file.name}{" "}
                            <span className="text-muted-foreground text-xs">({Math.ceil(file.bytes / 1024)} KiB)</span>
                          </span>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            aria-label={t("removeFile", { name: file.name })}
                            onClick={() => {
                              setPendingEvidence(true);
                              setFiles((current) => current.filter((item) => item.name !== file.name));
                              setCoverageConfirmed(false);
                              setTargetScopeConfirmed(false);
                            }}
                          >
                            <XIcon />
                          </Button>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <label className="flex items-start gap-2 text-sm leading-relaxed">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={coverageConfirmed}
                      onChange={(event) => setCoverageConfirmed(event.target.checked)}
                    />
                    <span>{t("confirmCoverage")}</span>
                  </label>
                  <label className="flex items-start gap-2 text-sm leading-relaxed">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={targetScopeConfirmed}
                      onChange={(event) => setTargetScopeConfirmed(event.target.checked)}
                    />
                    <span>{t("confirmTarget")}</span>
                  </label>
                  <p className="text-muted-foreground text-xs leading-relaxed">{t("attestationHelp")}</p>
                </div>
              ) : (
                <div className="space-y-4 rounded-lg border p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Label htmlFor={`${fieldId}-splunk`}>{t("splunkConnection")}</Label>
                    <Link
                      href="/function/purple/sources/"
                      className="inline-flex items-center gap-1 text-xs underline underline-offset-2"
                    >
                      {t("manageSources")}
                      <ArrowUpRightIcon className="size-3" />
                    </Link>
                  </div>
                  {sourceError ? (
                    <Alert variant="destructive">
                      <AlertDescription>{sourceError}</AlertDescription>
                    </Alert>
                  ) : null}
                  <select
                    id={`${fieldId}-splunk`}
                    className={SELECT_CLASS}
                    value={sourceId}
                    onChange={(event) => {
                      const id = event.target.value;
                      setSourceId(id);
                      const source = sources.find((item) => item.id === id);
                      setSourcetypes(securitySourceSourcetypes(source).join(", "));
                    }}
                  >
                    <option value="">{t("chooseSource")}</option>
                    {sources.map((source) => (
                      <option key={source.id} value={source.id} disabled={!source.enabled || !source.credential_set}>
                        {source.name}
                        {!source.enabled || !source.credential_set ? ` · ${t("unavailableSource")}` : ""}
                      </option>
                    ))}
                  </select>
                  {!sources.length ? <p className="text-muted-foreground text-sm">{t("noSources")}</p> : null}
                  <div className="space-y-2">
                    <Label htmlFor={`${fieldId}-sourcetypes`}>{t("sourcetypes")}</Label>
                    <Input
                      id={`${fieldId}-sourcetypes`}
                      value={sourcetypes}
                      onChange={(event) => setSourcetypes(event.target.value)}
                    />
                    <p className="text-muted-foreground text-xs">{t("sourcetypesHelp")}</p>
                  </div>
                  <p className="text-muted-foreground text-xs leading-relaxed">{t("splunkHelp")}</p>
                  <p className="text-sm leading-relaxed">{t("splunkTargetMappingHelp", { field: mapping.target })}</p>
                </div>
              )}
              <details className="rounded-lg border p-4">
                <summary className="cursor-pointer font-medium text-sm">{t("mapping")}</summary>
                <p className="mt-3 text-muted-foreground text-xs leading-relaxed">{t("mappingHelp")}</p>
                <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {(Object.keys(mapping) as (keyof InvestigationMapping)[]).map((key) => (
                    <div key={key} className="space-y-1.5">
                      <Label htmlFor={`${fieldId}-map-${key}`}>{t(`fields.${key}`)}</Label>
                      <Input
                        id={`${fieldId}-map-${key}`}
                        value={mapping[key]}
                        onChange={(event) => {
                          setMapping((current) => ({ ...current, [key]: event.target.value }));
                          setCoverageConfirmed(false);
                          setTargetScopeConfirmed(false);
                        }}
                        maxLength={128}
                      />
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-muted-foreground text-xs leading-relaxed">{t("actionHelp")}</p>
              </details>
              {sourceKind === "splunk" ? (
                <div className="space-y-3">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void previewQuery()}
                    disabled={!selectedSource?.enabled || !selectedSource.credential_set}
                  >
                    {busy === "preview" ? <Spinner /> : <SearchIcon />}
                    {t("preview")}
                  </Button>
                  {validPreview ? (
                    <div className="space-y-2 rounded-lg border border-sky-500/30 p-4">
                      <p className="font-medium text-xs">{t("previewReady")}</p>
                      <pre className="overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                        {validPreview.query}
                      </pre>
                      <p className="text-muted-foreground text-xs">
                        {t("previewHelp", { revision: validPreview.source_revision })}
                      </p>
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-xs">{t("previewRequired")}</p>
                  )}
                </div>
              ) : null}
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  type="button"
                  onClick={() => void create()}
                  disabled={sourceKind === "file" ? !files.length || !fileLabel.trim() : !validPreview}
                >
                  {busy === "create" ? <Spinner /> : <UploadIcon />}
                  {t(sourceKind === "file" ? "analyzeFile" : "analyzeSplunk")}
                </Button>
                <p className="text-muted-foreground text-xs">{t("privacy")}</p>
              </div>
            </fieldset>
            {busy === "create" ? (
              <p role="status" className="mt-4 flex items-center gap-2 text-muted-foreground text-sm">
                <Spinner />
                {t(sourceKind === "splunk" ? "searching" : "analyzing")}
              </p>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="text-base">
              {ta("defensive.history")}
              {total !== null ? (
                <Badge variant="secondary" className="ml-2">
                  {total}
                </Badge>
              ) : null}
            </CardTitle>
            <CardDescription>{ta("defensive.historyHelp")}</CardDescription>
          </div>
          <Input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder={ta("defensive.filter")}
            aria-label={ta("defensive.filter")}
            className="w-full sm:w-64"
          />
        </CardHeader>
        <CardContent className="space-y-3">
          {busy === "load" && total === null ? <Skeleton className="h-24 w-full" /> : null}
          {truncated ? <p className="text-xs text-muted-foreground">{ta("defensive.truncated")}</p> : null}
          {!visibleCases.length && total !== null ? (
            <div className="rounded-lg border border-dashed p-6 text-center">
              <FileSearchIcon className="mx-auto mb-2 size-6 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">{ta(filter ? "defensive.noMatches" : "defensive.empty")}</p>
            </div>
          ) : null}
          <div className="grid gap-3 md:grid-cols-2">
            {visibleCases.map((item) => (
              <div
                key={item.id}
                className={`relative rounded-lg border transition-colors hover:bg-muted/50 ${record?.id === item.id ? "border-sky-500/50 bg-sky-500/5" : ""}`}
              >
                <button
                  type="button"
                  disabled={!!busy || deletingCase}
                  onClick={() => void openRecord(item.id)}
                  className="block w-full space-y-2 p-4 pr-12 text-left disabled:opacity-50"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-sm">{item.title || item.id}</span>
                    <Badge variant="outline">{item.source_kind === "splunk" ? "Splunk" : ta("defensive.file")}</Badge>
                    <Badge variant="secondary">{ta(item.complete ? "defensive.complete" : "defensive.partial")}</Badge>
                  </div>
                  <p className="line-clamp-2 text-sm text-muted-foreground">{item.summary}</p>
                  <p className="truncate text-xs text-muted-foreground">
                    {item.scope.target}
                    {item.scope.path_prefix} · {new Date(item.created_at).toLocaleString()}
                  </p>
                </button>
                <Button
                  type="button"
                  size="icon-sm"
                  variant="ghost"
                  className="absolute right-2 top-2 text-destructive hover:text-destructive"
                  disabled={!!busy || deletingCase}
                  aria-label={ta("defensive.deleteTarget", { name: item.title || item.id })}
                  onClick={() => setCaseToDelete(item)}
                >
                  <Trash2Icon />
                </Button>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
      <AlertDialog
        open={!!caseToDelete}
        onOpenChange={(open) => {
          if (!open && !deletingCase) setCaseToDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {ta("defensive.deleteTitle", { name: caseToDelete?.title || caseToDelete?.id || "" })}
            </AlertDialogTitle>
            <AlertDialogDescription>{ta("defensive.deleteDescription")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletingCase}>{ta("defensive.deleteCancel")}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deletingCase}
              onClick={(event) => {
                event.preventDefault();
                void deleteCase();
              }}
            >
              {deletingCase ? <Spinner /> : <Trash2Icon />}
              {ta(deletingCase ? "defensive.deleting" : "defensive.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      {record ? (
        <div ref={resultRef} className="scroll-mt-24 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/20 p-4">
            <div>
              <p className="font-medium">{record.title}</p>
              <p className="mt-1 text-xs text-muted-foreground">
                {ta("defensive.evidenceSaved", { n: record.collection.stats.selected })}
              </p>
            </div>
            {record.finding_id ? (
              <Button size="sm" variant="outline" asChild>
                <Link href={`/function/findings/detail/?id=${encodeURIComponent(record.finding_id)}`}>
                  {ta("defensive.relatedFinding")}
                  <ArrowUpRightIcon />
                </Link>
              </Button>
            ) : (
              <Badge variant="secondary">{ta("defensive.independent")}</Badge>
            )}
          </div>
          <InvestigationEvidenceNotice record={record} />
          <FindingInvestigationAgentPanel
            key={record.id}
            findingId=""
            record={record}
            apiClient={defensiveAgentApi}
            standalone
            pendingEvidence={newMode && pendingEvidence}
          />
          <InvestigationResult
            key={`evidence-${record.id}`}
            record={record}
            standalone
            exporting={exporting}
            onExport={() => void exportRecord()}
          />
        </div>
      ) : null}
    </div>
  );
}
export default function DefensivePage() {
  return (
    <React.Suspense
      fallback={
        <div className="p-6">
          <Skeleton className="h-64 w-full" />
        </div>
      }
    >
      <DefensivePageContent />
    </React.Suspense>
  );
}
