package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/hunting"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/Autumn-27/norma/llm"
)

// Opt-in only. The dedicated cloned database prevents a live test from
// modifying the user's scenarios, tasks, provider settings or source records.
func TestHuntLiveLLMAndSplunk(t *testing.T) {
	if os.Getenv("ARTEX_HUNT_LIVE") != "1" {
		t.Skip("set ARTEX_HUNT_LIVE=1 with an isolated cloned database and an explicit request")
	}
	if os.Getenv("ARTEX_HUNT_LIVE_PREFLIGHT") != "1" && os.Getenv("ARTEX_HUNT_LIVE_SEND_LOGS") != "approved" {
		t.Fatal("actual log transmission requires explicit approval; use preflight to inspect the payload first")
	}
	dsn, err := url.Parse(os.Getenv("ARTEX_PG_DSN"))
	if err != nil || strings.Trim(dsn.Path, "/") != "hunting_live" {
		t.Fatal("live test requires the dedicated hunting_live database")
	}
	dir := os.Getenv("ARTEX_HUNT_LIVE_EVIDENCE")
	if dir == "" {
		t.Fatal("private evidence directory is required")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(os.Getenv("ARTEX_HUNT_LIVE_JWT_FILE"))
	if err != nil {
		t.Fatal("cannot load saved source decryption key")
	}
	raw, err := os.ReadFile(os.Getenv("ARTEX_HUNT_LIVE_REQUEST"))
	if err != nil {
		t.Fatal(err)
	}
	var in huntRequest
	if err = json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	if !in.ScopeConfirmed || in.Scope.Target == "" || in.Scope.Start.IsZero() || in.Scope.End.IsZero() {
		t.Fatal("an explicit approved target, time window and source are required")
	}
	pg, err := db.Open(dsn.String())
	if err != nil {
		t.Fatal("cannot open isolated database")
	}
	defer pg.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &Server{ctx: ctx, jwtKey: []byte(strings.TrimSpace(string(key))), m: &Manager{pg: pg, dir: filepath.Join(dir, "work"), webSearchOn: true, webSearchBackend: "ddgs"}}
	before := liveScenarioFingerprint(t, pg)
	cfg, ok := s.loadLLMConfig()
	if !ok {
		t.Fatal("saved active LLM credentials are unavailable")
	}
	base, err := cfg.NewProvider()
	if err != nil {
		t.Fatal("saved provider configuration could not be initialized")
	}
	audit := &huntLiveProvider{base: base, secret: cfg.APIKey, dir: dir}
	s.llmProv = audit
	s.llmCfg = cfg
	s.llmOn = true
	source, err := s.huntSource(ctx, in.Request)
	if err != nil {
		t.Fatal("saved source revision/approved stream validation failed")
	}
	auth, err := s.securitySourceCredentials(source)
	if err != nil {
		t.Fatal("saved source credentials could not be decrypted")
	}
	preflight, err := securitysource.FetchInvestigation(ctx, source.Config, auth, in.Scope, in.Mapping, in.Sourcetypes, nil)
	if err != nil {
		t.Fatal("live Splunk preflight failed: ", audit.safeError(err))
	}
	writeLiveJSON(t, dir, "preflight.json", map[string]any{"events": len(preflight.Events), "stats": preflight.Stats, "scope": preflight.Scope, "query": preflight.Query, "complete": preflight.Complete})
	if os.Getenv("ARTEX_HUNT_LIVE_PREFLIGHT") == "1" {
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = os.Getenv("OPENAI_BASE_URL")
		}
		if baseURL == "" && (cfg.Provider() == "openai" || cfg.Provider() == "openai-responses") {
			baseURL = "https://api.openai.com/v1"
		}
		endpoint, _ := url.Parse(baseURL)
		fields := map[string]int{}
		paths := map[string]int{}
		for _, event := range preflight.Events {
			paths[event.Path]++
			var value map[string]json.RawMessage
			if json.Unmarshal([]byte(event.Raw), &value) == nil {
				for field := range value {
					fields[field]++
				}
			}
		}
		host := "configured provider"
		if endpoint != nil && endpoint.Hostname() != "" {
			host = endpoint.Hostname()
		}
		writeLiveJSON(t, dir, "transmission-preview.json", map[string]any{"model": cfg.Model, "provider_host": host, "scope": in.Scope, "events": len(preflight.Events), "raw_fields": fields, "paths": paths, "llm_called": false, "existing_scenarios_unchanged": before == liveScenarioFingerprint(t, pg)})
		t.Logf("preflight only: %d actual events; no model requests made", len(preflight.Events))
		return
	}
	t.Logf("live provider=%s model=%s; source=%d revision=%d; preflight events=%d", cfg.Provider(), cfg.Model, source.ID, source.Revision, len(preflight.Events))
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal("cannot create local API test session")
	}
	handler := s.Handler()
	request := func(method, path string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := request("POST", "/api/defensive/hunts", raw)
	if w.Code != 202 {
		t.Fatalf("live create returned %d: %s", w.Code, w.Body.String())
	}
	var run db.Hunt
	if err = json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(hunting.RunTimeout + 20*time.Second)
	lastSequence := 0
	for {
		current, err := pg.GetHunt(ctx, run.ID)
		if err != nil {
			t.Fatal("cannot read live run")
		}
		run = *current
		for _, event := range run.Events {
			if event.Sequence <= lastSequence {
				continue
			}
			lastSequence = event.Sequence
			var item hunting.Event
			_ = json.Unmarshal(event.Payload, &item)
			summary := item.Summary
			if event.Kind == "evidence_collection" {
				var proof investigationQueryProof
				_ = json.Unmarshal(event.Payload, &proof)
				summary = fmt.Sprintf("collected %d actual events", len(proof.Collection.Events))
			}
			t.Logf("event %d %s %s", event.Sequence, event.Kind, huntTextBytes(summary, 350))
		}
		writeLiveJSON(t, dir, "live-status.json", map[string]any{"id": run.ID, "status": run.Status, "events": len(run.Events), "updated_at": run.UpdatedAt})
		if run.Status != "queued" && run.Status != "running" {
			break
		}
		if time.Now().After(deadline) {
			request("POST", fmt.Sprintf("/api/defensive/hunts/%d/cancel", run.ID), nil)
			t.Fatal("live run did not terminate within its deadline")
		}
		select {
		case <-ctx.Done():
			t.Fatal("live test cancelled")
		case <-time.After(2 * time.Second):
		}
	}
	export := request("GET", fmt.Sprintf("/api/defensive/hunts/%d/export", run.ID), nil)
	if export.Code != 200 {
		t.Fatal("live evidence export failed")
	}
	if err = os.WriteFile(filepath.Join(dir, "export.json"), export.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var result hunting.Result
	_ = json.Unmarshal(run.Result, &result)
	after := liveScenarioFingerprint(t, pg)
	summary := map[string]any{"run_id": run.ID, "status": run.Status, "model": cfg.Model, "format": cfg.Provider(), "source_id": source.ID, "source_revision": source.Revision, "scope": in.Scope, "preflight_events": len(preflight.Events), "research_sources": result.Research.Sources, "cves": result.Research.CVEs, "design": result.Design, "usage": result.Investigation.Usage, "verification": result.Verification, "error": run.Error, "result_error": result.Error, "existing_scenarios_before": before, "existing_scenarios_after": after, "existing_scenarios_unchanged": before == after, "synthetic_telemetry": false, "real_llm": true, "real_splunk": true}
	writeLiveJSON(t, dir, "summary.json", summary)
	if before != after {
		t.Fatal("existing scenario data changed")
	}
	if run.Status != "completed" && run.Status != "insufficient_data" {
		t.Fatalf("live pipeline ended %s; inspect private evidence", run.Status)
	}
	if len(result.Research.Sources) == 0 || len(result.Design.Stages) == 0 || len(result.Investigation.Collections) == 0 || len(result.Verification.Stages) != len(result.Design.Stages) || result.Investigation.Usage.ModelCalls < 2 || result.Investigation.Usage.RemoteQueries < 1 {
		t.Fatal("live pipeline did not reach all engines")
	}
	t.Logf("live pipeline finished status=%s model_calls=%d remote_queries=%d assessments=%d", run.Status, result.Investigation.Usage.ModelCalls, result.Investigation.Usage.RemoteQueries, len(result.Verification.Stages))
}
func liveScenarioFingerprint(t *testing.T, pg *db.DB) string {
	t.Helper()
	var value string
	if err := pg.QueryRow(`SELECT md5(coalesce(string_agg(to_jsonb(s)::text,'' ORDER BY id),'')) FROM finding_defense_scenarios s`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
func writeLiveJSON(t *testing.T, dir, name string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// Log actual SDK responses only to the private evidence folder. Keys never
// enter requests/results; any provider errors are redacted before recording.
type huntLiveProvider struct {
	mu          sync.Mutex
	base        llm.Provider
	secret, dir string
	sequence    int
}

func (p *huntLiveProvider) safeError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if p.secret != "" {
		value = strings.ReplaceAll(value, p.secret, "[redacted]")
	}
	return huntTextBytes(value, 3000)
}
func (p *huntLiveProvider) record(kind string, message llm.Message, usage llm.Usage, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sequence++
	text := []string{}
	for _, block := range message.Content {
		if block.Type == llm.BlockText {
			text = append(text, block.Text)
		}
	}
	raw, _ := json.Marshal(map[string]any{"sequence": p.sequence, "kind": kind, "at": time.Now().UTC(), "usage": usage, "text": text, "error": p.safeError(err)})
	f, e := os.OpenFile(filepath.Join(p.dir, "provider-responses.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e == nil {
		_, _ = f.Write(append(raw, '\n'))
		_ = f.Close()
	}
}
func (p *huntLiveProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	m, reason, u, err := p.base.Complete(ctx, req)
	p.record("complete", m, u, err)
	return m, reason, u, err
}
func (p *huntLiveProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		acc := llm.NewAccumulator()
		var last error
		for ev, err := range p.base.Stream(ctx, req) {
			if err == nil {
				acc.Add(ev)
			} else {
				last = err
			}
			if !yield(ev, err) {
				break
			}
		}
		p.record("stream", llm.Message{}, acc.Usage, last)
	}
}
