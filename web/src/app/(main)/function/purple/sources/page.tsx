"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowLeftIcon, CableIcon, PencilIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

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
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { HttpError } from "@/lib/api";
import {
  type SecurityLogStream,
  type SecuritySource,
  type SecuritySourceConfig,
  type SecurityStreamTest,
  securityApi,
} from "@/lib/security-api";

const DEFAULT_STREAMS: SecurityLogStream[] = [
  { kind: "audit", index: "", sourcetype: "" },
  { kind: "alert", index: "", sourcetype: "" },
];
const MAX_STREAMS = 16;
const STREAM_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$/;

const DEFAULT_CONFIG: SecuritySourceConfig = {
  base_url: "",
  streams: DEFAULT_STREAMS,
  index: "",
  audit_sourcetype: "",
  alert_sourcetype: "",
  correlation_field: "artex_verification_id",
  action_field: "action",
  tls_fingerprint: "",
};
const CONFIG_FIELDS = ["correlation_field", "action_field", "tls_fingerprint"] as const;

function configuredStreams(config: SecuritySourceConfig): SecurityLogStream[] {
  if (config.streams?.length) return config.streams.map((stream) => ({ ...stream }));
  if (config.index) {
    return [
      { kind: "audit", index: config.index, sourcetype: config.audit_sourcetype ?? "" },
      { kind: "alert", index: config.index, sourcetype: config.alert_sourcetype ?? "" },
    ];
  }
  return DEFAULT_STREAMS.map((stream) => ({ ...stream }));
}

function editableConfig(config?: SecuritySourceConfig): SecuritySourceConfig {
  const base = config ?? DEFAULT_CONFIG;
  return {
    ...base,
    streams: configuredStreams(base),
    index: "",
    audit_sourcetype: "",
    alert_sourcetype: "",
  };
}

export default function PurpleSourcesPage() {
  const t = useTranslations("purple.sources");
  const tp = useTranslations("purple");
  const fieldId = React.useId();
  const streamRowSerial = React.useRef(2);
  const [streamRowIds, setStreamRowIds] = React.useState(["1", "2"]);
  const [sources, setSources] = React.useState<SecuritySource[] | null>(null);
  const [editing, setEditing] = React.useState<SecuritySource | null>(null);
  const [sourceToDelete, setSourceToDelete] = React.useState<SecuritySource | null>(null);
  const [name, setName] = React.useState("");
  const [config, setConfig] = React.useState<SecuritySourceConfig>(() => editableConfig());
  const [enabled, setEnabled] = React.useState(true);
  const [authMode, setAuthMode] = React.useState<"keep" | "token" | "basic">("token");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [token, setToken] = React.useState("");
  const [busy, setBusy] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const [loadError, setLoadError] = React.useState("");
  const [testResult, setTestResult] = React.useState<{ id: string; detail: string } | null>(null);
  const [streamTestResults, setStreamTestResults] = React.useState<Record<string, SecurityStreamTest>>({});
  const [discoveredIndexes, setDiscoveredIndexes] = React.useState<string[]>([]);
  const [discoveryMessage, setDiscoveryMessage] = React.useState("");
  const seq = React.useRef(0);

  const load = React.useCallback(async () => {
    const request = ++seq.current;
    setLoading(true);
    setLoadError("");
    try {
      const result = await securityApi.sources();
      if (request === seq.current) setSources(result.sources);
    } catch (e) {
      if (request === seq.current) setLoadError((e as Error).message);
    } finally {
      if (request === seq.current) setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
    return () => {
      seq.current++;
    };
  }, [load]);

  const edit = (source: SecuritySource | null) => {
    const nextConfig = editableConfig(source?.config);
    setEditing(source);
    setName(source?.name ?? "");
    setConfig(nextConfig);
    setStreamRowIds((nextConfig.streams ?? []).map(() => String(++streamRowSerial.current)));
    setEnabled(source?.enabled ?? true);
    setAuthMode(source?.credential_set ? "keep" : "token");
    setUsername("");
    setPassword("");
    setToken("");
    setError("");
    setDiscoveredIndexes([]);
    setDiscoveryMessage("");
  };

  const updateStream = (index: number, patch: Partial<SecurityLogStream>) => {
    setConfig((current) => ({
      ...current,
      streams: (current.streams ?? []).map((stream, position) =>
        position === index ? { ...stream, ...patch } : stream,
      ),
    }));
  };

  const addStream = (kind: SecurityLogStream["kind"]) => {
    if ((config.streams ?? []).length >= MAX_STREAMS) return;
    setConfig((current) => ({
      ...current,
      streams: [...(current.streams ?? []), { kind, index: "", sourcetype: "" }],
    }));
    setStreamRowIds((current) => [...current, String(++streamRowSerial.current)]);
  };

  const removeStream = (index: number) => {
    setConfig((current) => ({
      ...current,
      streams: (current.streams ?? []).filter((_, position) => position !== index),
    }));
    setStreamRowIds((current) => current.filter((_, position) => position !== index));
  };

  const discoverIndexes = async () => {
    if (!editing?.id || !editing.credential_set || busy) return;
    setBusy(`indexes:${editing.id}`);
    setDiscoveryMessage("");
    try {
      const result = await securityApi.indexes(editing.id);
      setDiscoveredIndexes(result.indexes);
      setDiscoveryMessage(
        t(result.indexes.length ? "indexesFound" : "indexesEmpty", {
          count: result.indexes.length,
        }),
      );
    } catch (caught) {
      setDiscoveryMessage((caught as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const save = async () => {
    if (busy) return;
    const streams = (config.streams ?? []).map((stream) => ({
      kind: stream.kind,
      index: stream.index.trim(),
      sourcetype: stream.sourcetype.trim(),
      ...(stream.label?.trim() ? { label: stream.label.trim() } : {}),
      ...(stream.asset?.trim() ? { asset: stream.asset.trim() } : {}),
    }));
    if (
      streams.length > MAX_STREAMS ||
      !streams.some((stream) => stream.kind === "audit") ||
      !streams.some((stream) => stream.kind === "alert")
    ) {
      setError(t("streamsRequired"));
      return;
    }
    if (streams.some((stream) => !STREAM_NAME.test(stream.index) || !STREAM_NAME.test(stream.sourcetype))) {
      setError(t("streamInvalid"));
      return;
    }
    const keys = streams.map((stream) => `${stream.index}\u0000${stream.sourcetype}`);
    if (new Set(keys).size !== keys.length) {
      setError(t("streamDuplicate"));
      return;
    }
    if ((authMode === "token" && !token.trim()) || (authMode === "basic" && (!username.trim() || !password))) {
      setError(t("credentialsRequired"));
      return;
    }
    setBusy("save");
    setError("");
    try {
      let credentials: { token?: string; username?: string; password?: string } = {};
      if (authMode === "token") credentials = { token: token.trim() };
      else if (authMode === "basic") credentials = { username: username.trim(), password };
      await securityApi.saveSource(editing?.id ?? null, {
        name: name.trim(),
        config: {
          ...config,
          streams,
          index: "",
          audit_sourcetype: "",
          alert_sourcetype: "",
        },
        enabled,
        expected_revision: editing?.revision ?? 0,
        ...credentials,
      });
      edit(null);
      setTestResult(null);
      setStreamTestResults({});
      await load();
      toast.success(t("saved"));
    } catch (e) {
      if (e instanceof HttpError && e.status === 409) {
        await load();
        setError(t("conflict"));
      } else setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const test = async (source: SecuritySource) => {
    if (busy) return;
    setBusy(source.id);
    setError("");
    setTestResult(null);
    try {
      const result = await securityApi.testSource(source.id);
      if (result.ok) setTestResult({ id: source.id, detail: result.detail });
      else setError(result.detail);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const testStream = async (source: SecuritySource, streamIndex: number) => {
    if (busy) return;
    const key = `${source.id}:${source.revision}:${streamIndex}`;
    setBusy(`stream:${key}`);
    setError("");
    try {
      const result = await securityApi.testStream(source.id, streamIndex);
      setStreamTestResults((current) => ({ ...current, [key]: result }));
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const deleteSource = async () => {
    if (!sourceToDelete || busy) return;
    const source = sourceToDelete;
    setBusy(`delete:${source.id}`);
    setError("");
    try {
      await securityApi.deleteSource(source.id, source.revision);
      setSources((current) => current?.filter((item) => item.id !== source.id) ?? null);
      if (editing?.id === source.id) edit(null);
      if (testResult?.id === source.id) setTestResult(null);
      setSourceToDelete(null);
      toast.success(t("deleted"));
      await load();
    } catch (caught) {
      const message =
        caught instanceof HttpError && caught.status === 409 ? t("deleteConflict") : (caught as Error).message;
      if (caught instanceof HttpError && caught.status === 409) {
        setSourceToDelete(null);
        await load();
      }
      setError(message);
      toast.error(message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-1 flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b px-4 py-3 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Button asChild variant="ghost" size="sm">
          <Link href="/function/purple">
            <ArrowLeftIcon />
            {tp("title")}
          </Link>
        </Button>
        <CableIcon className="size-5 text-violet-500" />
        <h1 className="font-semibold">{t("title")}</h1>
      </header>
      <div className="flex flex-col gap-5 p-4 lg:p-6">
        <p className="max-w-3xl text-sm text-muted-foreground">{t("description")}</p>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        <div className="grid items-start gap-5 xl:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>{editing ? t("editTitle", { name: editing.name }) : t("createTitle")}</CardTitle>
              <CardDescription>{t("formDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void save();
                }}
              >
                <fieldset className="flex flex-col gap-4" disabled={!!busy}>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-name`}>{t("name")}</Label>
                    <Input
                      id={`${fieldId}-name`}
                      required
                      maxLength={120}
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-url`}>{t("base_url")}</Label>
                    <Input
                      id={`${fieldId}-url`}
                      type="url"
                      pattern="https://.+"
                      placeholder="https://splunk.example.com:8089"
                      required
                      maxLength={2048}
                      value={config.base_url}
                      onChange={(event) => setConfig({ ...config, base_url: event.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">{t("urlHelp")}</p>
                  </div>
                  <div className="flex flex-col gap-3 rounded-lg border p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <p className="text-sm font-medium">{t("streamsTitle")}</p>
                        <p className="text-xs text-muted-foreground">{t("streamsHelp")}</p>
                      </div>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={!editing?.credential_set || !!busy}
                        onClick={() => void discoverIndexes()}
                      >
                        {busy?.startsWith("indexes:") ? <Spinner /> : <RefreshCwIcon />}
                        {t("discoverIndexes")}
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {editing?.credential_set ? t("manualIndexHelp") : t("discoverIndexesAfterSave")}
                    </p>
                    {discoveryMessage ? <p className="text-xs text-muted-foreground">{discoveryMessage}</p> : null}
                    <datalist id={`${fieldId}-index-options`}>
                      {discoveredIndexes.map((index) => (
                        <option key={index} value={index} />
                      ))}
                    </datalist>
                    {(config.streams ?? []).map((stream, index) => {
                      const kindCount = (config.streams ?? []).filter((item) => item.kind === stream.kind).length;
                      return (
                        <div
                          key={streamRowIds[index]}
                          className="flex flex-col gap-3 rounded-md border bg-muted/20 p-3"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <Badge variant="secondary">{t(`streamKind.${stream.kind}`)}</Badge>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              disabled={kindCount <= 1}
                              onClick={() => removeStream(index)}
                              aria-label={t("removeStream")}
                            >
                              <Trash2Icon />
                              {t("removeStream")}
                            </Button>
                          </div>
                          <div className="grid gap-3 sm:grid-cols-2">
                            <div className="flex flex-col gap-2">
                              <Label htmlFor={`${fieldId}-stream-${index}-index`}>{t("index")}</Label>
                              <Input
                                id={`${fieldId}-stream-${index}-index`}
                                list={`${fieldId}-index-options`}
                                required
                                maxLength={128}
                                value={stream.index}
                                onChange={(event) => updateStream(index, { index: event.target.value })}
                              />
                            </div>
                            <div className="flex flex-col gap-2">
                              <Label htmlFor={`${fieldId}-stream-${index}-sourcetype`}>{t("sourcetype")}</Label>
                              <Input
                                id={`${fieldId}-stream-${index}-sourcetype`}
                                required
                                maxLength={128}
                                value={stream.sourcetype}
                                onChange={(event) => updateStream(index, { sourcetype: event.target.value })}
                              />
                            </div>
                            <div className="flex flex-col gap-2">
                              <Label htmlFor={`${fieldId}-stream-${index}-label`}>{t("streamLabel")}</Label>
                              <Input
                                id={`${fieldId}-stream-${index}-label`}
                                maxLength={120}
                                value={stream.label ?? ""}
                                onChange={(event) => updateStream(index, { label: event.target.value })}
                              />
                            </div>
                            <div className="flex flex-col gap-2">
                              <Label htmlFor={`${fieldId}-stream-${index}-asset`}>{t("streamAsset")}</Label>
                              <Input
                                id={`${fieldId}-stream-${index}-asset`}
                                maxLength={256}
                                value={stream.asset ?? ""}
                                onChange={(event) => updateStream(index, { asset: event.target.value })}
                              />
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    <p className="text-xs text-muted-foreground">{t("streamAssetHelp")}</p>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={(config.streams ?? []).length >= MAX_STREAMS}
                        onClick={() => addStream("audit")}
                      >
                        {t("addAuditStream")}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={(config.streams ?? []).length >= MAX_STREAMS}
                        onClick={() => addStream("alert")}
                      >
                        {t("addAlertStream")}
                      </Button>
                    </div>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    {CONFIG_FIELDS.map((key) => (
                      <div key={key} className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-${key}`}>{t(key)}</Label>
                        <Input
                          id={`${fieldId}-${key}`}
                          required={key !== "tls_fingerprint"}
                          maxLength={128}
                          value={config[key]}
                          onChange={(event) => setConfig({ ...config, [key]: event.target.value })}
                        />
                      </div>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">{t("fingerprintHelp")}</p>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-auth`}>{t("authentication")}</Label>
                    <select
                      id={`${fieldId}-auth`}
                      className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                      value={authMode}
                      onChange={(event) => {
                        setAuthMode(event.target.value as "keep" | "token" | "basic");
                        setUsername("");
                        setPassword("");
                        setToken("");
                      }}
                    >
                      {editing?.credential_set ? <option value="keep">{t("auth.keep")}</option> : null}
                      <option value="token">{t("auth.token")}</option>
                      <option value="basic">{t("auth.basic")}</option>
                    </select>
                  </div>
                  {authMode === "token" ? (
                    <div className="flex flex-col gap-2">
                      <Label htmlFor={`${fieldId}-token`}>{t("token")}</Label>
                      <Input
                        id={`${fieldId}-token`}
                        type="password"
                        autoComplete="new-password"
                        required
                        maxLength={8192}
                        value={token}
                        onChange={(event) => setToken(event.target.value)}
                      />
                    </div>
                  ) : null}
                  {authMode === "basic" ? (
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-username`}>{t("username")}</Label>
                        <Input
                          id={`${fieldId}-username`}
                          autoComplete="off"
                          required
                          maxLength={256}
                          value={username}
                          onChange={(event) => setUsername(event.target.value)}
                        />
                      </div>
                      <div className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-password`}>{t("password")}</Label>
                        <Input
                          id={`${fieldId}-password`}
                          type="password"
                          autoComplete="new-password"
                          required
                          maxLength={8192}
                          value={password}
                          onChange={(event) => setPassword(event.target.value)}
                        />
                      </div>
                    </div>
                  ) : null}
                  <p className="text-xs text-muted-foreground">{t("credentialsHelp")}</p>
                  <div className="flex items-center gap-2">
                    <input
                      id={`${fieldId}-enabled`}
                      type="checkbox"
                      checked={enabled}
                      onChange={(event) => setEnabled(event.target.checked)}
                    />
                    <Label htmlFor={`${fieldId}-enabled`}>{t("enabled")}</Label>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button type="submit" disabled={!name.trim() || !config.base_url.trim()}>
                      {busy === "save" ? <Spinner /> : null}
                      {t("save")}
                    </Button>
                    <Button type="button" variant="ghost" onClick={() => edit(null)}>
                      {editing ? t("cancelEdit") : t("clear")}
                    </Button>
                  </div>
                </fieldset>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
              <CardTitle>{t("listTitle")}</CardTitle>
              <Button variant="ghost" size="sm" disabled={loading || !!busy} onClick={() => void load()}>
                <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
                {tp("refresh")}
              </Button>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {loadError ? (
                <Alert variant="destructive">
                  <AlertDescription>{loadError}</AlertDescription>
                </Alert>
              ) : null}
              {sources === null && loading ? <Skeleton className="h-24" /> : null}
              {sources?.length === 0 ? <p className="text-sm text-muted-foreground">{t("empty")}</p> : null}
              {sources?.map((source) => (
                <div key={source.id} className="rounded-lg border p-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="font-medium">{source.name}</p>
                      <p className="mt-1 break-all text-xs text-muted-foreground">{source.config.base_url}</p>
                    </div>
                    <Badge variant="outline">{source.enabled ? t("active") : t("disabled")}</Badge>
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">
                    {t("revision", { n: source.revision })} ·{" "}
                    {source.credential_set ? t("credentialsSet") : t("credentialsMissing")}
                  </p>
                  <div className="mt-3 flex flex-col gap-2">
                    {configuredStreams(source.config).map((stream, streamIndex) => {
                      const key = `${source.id}:${source.revision}:${streamIndex}`;
                      const result = streamTestResults[key];
                      return (
                        <div key={key} className="rounded-md border p-2 text-xs">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex flex-wrap items-center gap-2">
                              <Badge variant="secondary">{t(`streamKind.${stream.kind}`)}</Badge>
                              <span className="font-medium">
                                {stream.label || `${stream.index} · ${stream.sourcetype}`}
                              </span>
                              {stream.label ? (
                                <span className="text-muted-foreground">
                                  {stream.index} · {stream.sourcetype}
                                </span>
                              ) : null}
                              {stream.asset ? (
                                <span className="text-muted-foreground">
                                  {t("streamAssetValue", { asset: stream.asset })}
                                </span>
                              ) : null}
                            </div>
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              disabled={!!busy || !source.credential_set}
                              onClick={() => void testStream(source, streamIndex)}
                            >
                              {busy === `stream:${key}` ? <Spinner /> : <CableIcon />}
                              {t("testStream")}
                            </Button>
                          </div>
                          {result ? (
                            <div
                              className={`mt-2 ${result.searchable ? "text-teal-700 dark:text-teal-300" : "text-destructive"}`}
                            >
                              <p>{result.searchable ? t("streamSearchable") : t("streamUnsearchable")}</p>
                              {result.searchable ? (
                                <p>{result.has_recent_events ? t("streamRecentEvents") : t("streamNoRecentEvents")}</p>
                              ) : null}
                              <p>{result.detail}</p>
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" disabled={!!busy} onClick={() => edit(source)}>
                      <PencilIcon />
                      {t("edit")}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={!!busy || !source.credential_set}
                      onClick={() => void test(source)}
                    >
                      {busy === source.id ? <Spinner /> : <CableIcon />}
                      {t("testConnection")}
                    </Button>
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      disabled={!!busy}
                      onClick={() => setSourceToDelete(source)}
                    >
                      <Trash2Icon />
                      {t("delete")}
                    </Button>
                  </div>
                  {testResult?.id === source.id ? (
                    <p className="mt-3 text-sm text-teal-700 dark:text-teal-300">{testResult.detail}</p>
                  ) : null}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
        <AlertDialog
          open={!!sourceToDelete}
          onOpenChange={(open) => {
            if (!open && !busy?.startsWith("delete:")) setSourceToDelete(null);
          }}
        >
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("deleteTitle", { name: sourceToDelete?.name ?? "" })}</AlertDialogTitle>
              <AlertDialogDescription>{t("deleteDescription")}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={!!busy}>{t("deleteCancel")}</AlertDialogCancel>
              <AlertDialogAction
                variant="destructive"
                disabled={!!busy}
                onClick={(event) => {
                  event.preventDefault();
                  void deleteSource();
                }}
              >
                {busy?.startsWith("delete:") ? <Spinner /> : <Trash2Icon />}
                {t(busy?.startsWith("delete:") ? "deleting" : "delete")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </div>
  );
}
