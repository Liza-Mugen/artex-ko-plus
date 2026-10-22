package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
)

func defensiveAPIFixture(t *testing.T) (*Server, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN is required for isolated PostgreSQL integration tests")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	s := &Server{m: &Manager{pg: pg}, jwtKey: []byte("defensive-test-only-signing-key-32-bytes"), ctx: ctx}
	t.Cleanup(func() {
		cancel()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			s.investigationMu.Lock()
			n := len(s.investigationCancel)
			s.investigationMu.Unlock()
			if n == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("case worker did not stop")
	})
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	return s, request
}
func defensiveAPIInput() defensiveCaseRequest {
	scope := investigation.Scope{Target: "app.example", PathPrefix: "/ftp", Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Add(-time.Minute)}
	return defensiveCaseRequest{Title: "Independent incident", Question: "접근 로그의 근거를 확인하세요.", Scope: scope, Mapping: investigation.DefaultMapping(), SourceKind: "file", FileLabel: "original web log", CoverageConfirmed: true, Files: []investigation.InputFile{{Name: "independent.jsonl", Content: fmt.Sprintf(`{"timestamp":%q,"id":"independent-raw-event","target":"app.example","path":"/ftp/initial.txt"}`, scope.Start.Add(time.Minute).Format(time.RFC3339Nano))}}}
}
func createAPICase(t *testing.T, s *Server, request func(string, string, string) *httptest.ResponseRecorder, in defensiveCaseRequest) *db.DefensiveCase {
	t.Helper()
	raw, _ := json.Marshal(in)
	w := request("POST", "/api/defensive/cases", string(raw))
	if w.Code != 201 {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	var c db.DefensiveCase
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM defensive_cases WHERE id=$1`, c.ID) })
	return &c
}
func waitDefensiveCaseRun(t *testing.T, s *Server, run *db.DefensiveCaseRun) *db.DefensiveCaseRun {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, err := s.m.pg.GetDefensiveCaseRun(t.Context(), run.CaseID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status != "queued" && current.Status != "running" {
			return current
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("case agent did not settle")
	return nil
}
func TestDefensiveCaseAuthAndRequestValidation(t *testing.T) {
	s := &Server{jwtKey: []byte("test-only")}
	for _, route := range []struct{ method, path string }{{"GET", "/api/defensive/cases"}, {"POST", "/api/defensive/cases"}, {"POST", "/api/defensive/cases/preview"}, {"GET", "/api/defensive/cases/1/export"}, {"DELETE", "/api/defensive/cases/1"}, {"POST", "/api/defensive/cases/1/runs"}, {"POST", "/api/defensive/cases/1/runs/1/cancel"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatal("unprotected case route", route.path, w.Code)
		}
	}
	in := defensiveAPIInput()
	if err := validateDefensiveCaseRequest(in); err != nil {
		t.Fatal(err)
	}
	in.FindingID = 3
	if err := validateDefensiveCaseRequest(in); err == nil {
		t.Fatal("unversioned optional link accepted")
	}
	in = defensiveAPIInput()
	in.SourceID = 2
	if err := validateDefensiveCaseRequest(in); err == nil {
		t.Fatal("file request with remote source accepted")
	}
}
func TestDefensiveCaseDeleteAPI(t *testing.T) {
	s, request := defensiveAPIFixture(t)
	c := createAPICase(t, s, request, defensiveAPIInput())
	path := fmt.Sprintf("/api/defensive/cases/%d", c.ID)
	run, created, err := s.m.pg.CreateDefensiveCaseRun(t.Context(), c.ID, json.RawMessage(`{}`))
	if err != nil || !created {
		t.Fatal("create active run", err)
	}
	if w := request("DELETE", path, ""); w.Code != 409 {
		t.Fatal("active deletion", w.Code, w.Body.String())
	}
	if _, err := s.m.pg.CancelDefensiveCaseRun(t.Context(), c.ID, run.ID); err != nil {
		t.Fatal("cancel", err)
	}
	w := request("DELETE", path, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), fmt.Sprintf(`"deleted":"%d"`, c.ID)) {
		t.Fatal("delete", w.Code, w.Body.String())
	}
	if w = request("GET", path, ""); w.Code != 404 {
		t.Fatal("deleted case still readable", w.Code)
	}
	if w = request("DELETE", path, ""); w.Code != 404 {
		t.Fatal("repeated deletion", w.Code)
	}
}
func TestDefensiveCaseFileNoFindingAndExplicitExport(t *testing.T) {
	s, request := defensiveAPIFixture(t)
	var before, after int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM findings`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	in := defensiveAPIInput()
	in.Mapping = investigation.Mapping{}
	c := createAPICase(t, s, request, in)
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM findings`).Scan(&after); err != nil || before != after {
		t.Fatal("case fabricated finding", err)
	}
	if c.FindingID != 0 || c.FindingSnapshot != nil || c.Analysis.ObservedCount != 1 || c.Collection.Files[0].Content != "" {
		t.Fatal("unexpected standalone case")
	}
	w := request("GET", "/api/defensive/cases", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "independent-raw-event") {
		t.Fatal("case list leaked evidence", w.Code)
	}
	w = request("GET", fmt.Sprintf("/api/defensive/cases/%d/export", c.ID), "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "independent-raw-event") || w.Header().Get("Content-Disposition") == "" {
		t.Fatal("missing original export")
	}
	w = request("POST", fmt.Sprintf("/api/defensive/cases/%d/runs", c.ID), `{}`)
	if w.Code != 503 {
		t.Fatal("unready model created work", w.Code)
	}
	runs, err := s.m.pg.ListDefensiveCaseRuns(t.Context(), c.ID)
	if err != nil || len(runs) != 0 {
		t.Fatal("no-LLM run saved", err)
	}
	in.CoverageConfirmed = false
	c2 := createAPICase(t, s, request, in)
	if c2.Collection.Complete {
		t.Fatal("unconfirmed coverage complete")
	}
}
func TestDefensiveCaseAgentAsyncNoFinding(t *testing.T) {
	s, request := defensiveAPIFixture(t)
	c := createAPICase(t, s, request, defensiveAPIInput())
	p := &investigationHTTPProvider{}
	s.llmOn = true
	s.llmProv = p
	s.llmCfg = agent.Config{Model: "local-scripted-mock", Stream: false}
	path := fmt.Sprintf("/api/defensive/cases/%d/runs", c.ID)
	w := request("POST", path, `{}`)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var run db.DefensiveCaseRun
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	done := waitDefensiveCaseRun(t, s, &run)
	if done.Status != "insufficient_data" || done.Usage.ModelCalls != 1 || len(done.Events) == 0 {
		t.Fatal("actual planner harness not used", done.Status, done.Usage)
	}
	var report agent.InvestigatorReport
	if err := json.Unmarshal(done.Result, &report); err != nil || len(report.Gaps) == 0 {
		t.Fatal("missing grounded report", err)
	}
	w = request("GET", fmt.Sprintf("%s/%d/export", path, done.ID), "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "independent-raw-event") {
		t.Fatal("agent export lost base evidence")
	}
}
func TestDefensiveCaseAgentCancelIdempotentAndSharedBudget(t *testing.T) {
	s, request := defensiveAPIFixture(t)
	c := createAPICase(t, s, request, defensiveAPIInput())
	c2 := createAPICase(t, s, request, defensiveAPIInput())
	p := &investigationHTTPProvider{block: true, started: make(chan struct{})}
	s.llmOn = true
	s.llmProv = p
	s.llmCfg = agent.Config{Model: "local-blocked-mock", Stream: false}
	path := fmt.Sprintf("/api/defensive/cases/%d/runs", c.ID)
	w := request("POST", path, `{}`)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var run db.DefensiveCaseRun
	_ = json.Unmarshal(w.Body.Bytes(), &run)
	select {
	case <-p.started:
	case <-time.After(3 * time.Second):
		t.Fatal("mock model did not start")
	}
	w = request("POST", path, `{}`)
	var repeat db.DefensiveCaseRun
	_ = json.Unmarshal(w.Body.Bytes(), &repeat)
	if w.Code != 202 || repeat.ID != run.ID || p.calls.Load() != 1 {
		t.Fatal("repeated start duplicated model work")
	}
	if w = request("POST", fmt.Sprintf("/api/defensive/cases/%d/runs", c2.ID), `{}`); w.Code != 409 {
		t.Fatal("parallel case budget not blocked", w.Code)
	}
	// Legacy finding AI runs consume the same runtime concurrency slot.
	id, err := s.m.pg.AddFinding(0, 0, "CASE_BUDGET_TEST", "fixture", "low", "source", "evidence", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.DeleteFinding(id) })
	legacy := investigationAPIInput(t, s, id)
	raw, _ := json.Marshal(legacy)
	w = request("POST", fmt.Sprintf("/api/exploration/findings/%d/investigations", id), string(raw))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var base db.FindingInvestigation
	_ = json.Unmarshal(w.Body.Bytes(), &base)
	if w = request("POST", fmt.Sprintf("/api/exploration/findings/%d/investigations/%d/agent-runs", id, base.ID), `{}`); w.Code != 409 {
		t.Fatal("case+finding shared budget bypassed", w.Code)
	}
	w = request("POST", fmt.Sprintf("%s/%d/cancel", path, run.ID), `{}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	done := waitDefensiveCaseRun(t, s, &run)
	if done.Status != "cancelled" {
		t.Fatal("cancel not durable")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s.investigationMu.Lock()
		n := len(s.investigationCancel)
		s.investigationMu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	done, err = s.m.pg.GetDefensiveCaseRun(t.Context(), c.ID, run.ID)
	if err != nil || done.Status != "cancelled" {
		t.Fatal("late callback overwrote cancellation", err)
	}
	// Existing legacy work also blocks a standalone case, including queued work.
	s.investigationMu.Lock()
	s.investigationCancel = map[int64]context.CancelFunc{123: func() {}}
	s.investigationMu.Unlock()
	if w = request("POST", fmt.Sprintf("/api/defensive/cases/%d/runs", c2.ID), `{}`); w.Code != 409 {
		t.Fatal("legacy+case shared budget bypassed", w.Code)
	}
	s.investigationMu.Lock()
	delete(s.investigationCancel, 123)
	s.investigationMu.Unlock()
}

func TestDefensiveCaseMarkersGlobalWindowAndUntrustedValues(t *testing.T) {
	start := time.Now().UTC().Add(-10 * time.Minute)
	end := start.Add(time.Minute)
	const marker = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	c := investigation.Collection{Events: []investigation.Event{{ID: "in-window", Timestamp: start, VerificationID: marker, KnownARTEX: true}, {ID: "outside", Timestamp: end, VerificationID: marker, KnownARTEX: true}, {ID: "unregistered", Timestamp: start, VerificationID: "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", KnownARTEX: false}}, Stats: investigation.Stats{KnownARTEX: 2, UnrecognizedMarkers: 1}}
	boundDefensiveCaseMarkers(&c, []db.InvestigationVerification{{ID: marker, Start: start, End: end}})
	if !c.Events[0].KnownARTEX || c.Events[1].KnownARTEX || c.Events[2].KnownARTEX || c.Stats.KnownARTEX != 1 || c.Stats.UnrecognizedMarkers != 2 {
		t.Fatal("global marker classification ignored actual evidence window")
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "전체 등록") || strings.Contains(c.Warnings[0], "같은 취약점") {
		t.Fatal("standalone case misleadingly scoped marker to a finding")
	}
}
