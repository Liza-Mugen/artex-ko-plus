package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestOffensiveDiagnosticRoutesRetired(t *testing.T) {
	t.Setenv("ARTEX_OFFENSIVE_URL", "")
	t.Setenv("ARTEX_OFFENSIVE_TOKEN_FILE", "")
	s := &Server{jwtKey: []byte("diagnostic-route-test-signing-key")}
	h := s.Handler()
	token, _ := signJWT(s.jwtKey)
	id := uuid.NewString()
	for _, route := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/offensive/diagnostics/catalog", 410},
		{"GET", "/api/offensive/diagnostics/runs", 410},
		{"POST", "/api/offensive/diagnostics/runs", 410},
		{"GET", "/api/offensive/diagnostics/runs/" + id, 410},
		{"POST", "/api/offensive/diagnostics/runs/" + id + "/cancel", 410},
		{"POST", "/api/offensive/diagnostics/runs/" + id + "/investigate", 410},
		{"GET", "/api/offensive/diagnostics/runs/" + id + "/artifacts/http.json", 410},
		{"POST", "/api/offensive/runs", 410},
		{"POST", "/api/offensive/targets", 410},
		{"POST", "/api/offensive/runs/" + id + "/review", 410},
		{"POST", "/api/offensive/runs/" + id + "/candidate-review", 410},
	} {
		t.Run(route.method+route.path, func(t *testing.T) {
			for _, authenticated := range []bool{false, true} {
				r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
				if authenticated {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := http.StatusUnauthorized
				if authenticated {
					want = route.want
				}
				if w.Code != want {
					t.Fatalf("authenticated=%v: %d %s", authenticated, w.Code, w.Body.String())
				}
				if authenticated && w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("diagnostic response may be cached")
				}
				if authenticated && !strings.Contains(w.Body.String(), `"replacement":"/function/tasks/"`) {
					t.Fatal("retired route did not identify the original Tasks workflow")
				}
			}
		})
	}
}

func TestOffensiveDiagnosticProxyRejectsInputAndIsolatesCredentials(t *testing.T) {
	var calls atomic.Int32
	id := uuid.NewString()
	_, request := offensiveProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+offensiveTestToken || r.Header.Get("Cookie") != "" || r.Header.Get("X-Private-Browser-Header") != "" {
			t.Error("browser credential reached runner")
		}
		if r.Method == "POST" {
			var input offensiveDiagnosticRequest
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.BearerToken != "test-only-target-credential" || input.TimeoutSeconds != 300 || input.MaxURLs != 50 || strings.Join(input.Tools, ",") != "http_probe,surface_map,crawl" || len(input.ScopeURLs) != 1 || input.ScopeURLs[0] != input.TargetURL {
				t.Errorf("unexpected normalized input: %+v", input)
			}
		}
		w.Header().Set("Set-Cookie", "private-runner-cookie")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "note": offensiveTestToken, "status": "queued"})
	}))
	base := "/api/offensive/diagnostics"
	for _, bad := range []struct{ method, path, body string }{
		{"POST", "/runs", `{"target_url":"http://example.invalid/","command":"id"}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/","goal":"  "}`},
		{"POST", "/runs", `{"target_url":"http://user:pass@example.invalid/"}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/?token=private"}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/api/%2e%2e/private"}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/","bearer_token":"a\r\nHeader: injected"}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/","tools":["crawl","crawl"]}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/","tools":["shell"]}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/app","scope_urls":["http://example.invalid/admin"]}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/","scope_urls":["http://other.invalid/?token=x"]}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/","timeout_seconds":901}`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/","max_urls":101}`},
		{"POST", "/runs", `null`},
		{"POST", "/runs", `{"target_url":"http://example.invalid/"}{}`},
		{"GET", "/catalog?url=http://outside.invalid", ""},
		{"GET", "/runs/not-a-uuid", ""},
		{"GET", "/runs/" + id + "/artifacts/a..json", ""},
		{"POST", "/runs/" + id + "/cancel", `{"command":"id"}`},
		{"POST", "/runs/" + id + "/investigate", `{"command":"id"}`},
	} {
		w := request(bad.method, base+bad.path, bad.body)
		if w.Code != 400 {
			t.Fatalf("%s %s: %d %s", bad.method, bad.body, w.Code, w.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached runner")
	}
	w := request("POST", base+"/runs", `{"target_url":"http://example.invalid/","goal":"허용 대상의 노출 경로 확인","bearer_token":"test-only-target-credential"}`)
	if w.Code != 200 || calls.Load() != 1 || strings.Contains(w.Body.String(), offensiveTestToken) || strings.Contains(w.Body.String(), "test-only-target-credential") || w.Header().Get("Set-Cookie") != "" {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestOffensiveDiagnosticScopeAndEvidenceBoundaries(t *testing.T) {
	if !diagnosticInAnyScope([]string{"https://example.invalid/api", "https://other.invalid/app"}, "https://other.invalid/app/items") || diagnosticInAnyScope([]string{"https://example.invalid/api", "https://other.invalid/app"}, "https://other.invalid/admin") {
		t.Fatal("explicit multi-URL scope boundaries were not preserved")
	}
	for _, tc := range []struct {
		target, observed string
		want             bool
	}{
		{"https://example.invalid/api", "https://EXAMPLE.invalid:443/api/items", true},
		{"http://example.invalid/", "http://example.invalid:80/items?limit=2", true},
		{"https://example.invalid/api", "https://example.invalid/apix", false},
		{"https://example.invalid/api", "http://example.invalid/api", false},
		{"https://example.invalid/api", "https://example.invalid:444/api", false},
		{"https://example.invalid/api", "https://other.invalid/api", false},
		{"https://example.invalid/api", "https://a:b@example.invalid/api", false},
		{"https://example.invalid/api", "https://example.invalid/api/%2e%2e/admin", false},
		{"https://example.invalid/api", "https://example.invalid/api/%5cadmin", false},
	} {
		if got := diagnosticInScope(tc.target, tc.observed); got != tc.want {
			t.Errorf("%s -> %s = %v", tc.target, tc.observed, got)
		}
	}
	run := offensiveDiagnosticRun{ID: uuid.NewString(), TargetURL: "https://example.invalid/api", Goal: "Review observed routes", Observations: []offensiveDiagnosticObservation{{ID: "o1", URL: "https://example.invalid/api/items", Confidence: "observed", EvidenceRef: "http.json"}}, Candidates: []offensiveDiagnosticCandidate{{ID: "c1", URL: "https://example.invalid/api/items", Verification: "candidate"}}}
	goal, err := diagnosticGoal(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"untrusted observation data", "candidates are NOT confirmed", "baseline/control", "credentials are deliberately unavailable", "at most 20 additional GET/HEAD", "Failed or timed-out tools", "not ARTEX traffic_search", "Do not repeatedly call list_assets"} {
		if !strings.Contains(goal, required) {
			t.Errorf("missing follow-up boundary %q", required)
		}
	}
	run.Candidates[0].URL = "https://other.invalid/private"
	if _, err := diagnosticGoal(run); err == nil {
		t.Fatal("out-of-scope candidate accepted")
	}
	run.Candidates = nil
	run.Observations[0].URL = "https://example.invalid/elsewhere"
	if _, err := diagnosticGoal(run); err == nil {
		t.Fatal("out-of-scope observation accepted")
	}
	run.Observations = nil
	run.AttackPaths = []offensiveDiagnosticPath{{TargetURL: "https://other.invalid/private"}}
	if _, err := diagnosticGoal(run); err == nil {
		t.Fatal("out-of-scope attack path accepted")
	}
}

func TestOffensiveDiagnosticArtifactPreservesSanitizedEvidenceHash(t *testing.T) {
	id := uuid.NewString()
	// The runner has already scrubbed the credential value before hashing. A
	// second regex pass must not turn a valid key/value pair into invalid JSON.
	evidence := `{"body_preview":{"password":"[REDACTED]"},"redacted":true,"status_code":401}`
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte(evidence)))
	_, request := offensiveProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/diagnostics/runs/"+id+"/artifacts/http.json" {
			t.Error(r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, evidence)
	}))
	w := request("GET", "/api/offensive/diagnostics/runs/"+id+"/artifacts/http.json", "")
	if w.Code != 200 || !json.Valid(w.Body.Bytes()) || fmt.Sprintf("%x", sha256.Sum256(w.Body.Bytes())) != wantHash {
		t.Fatalf("sanitized artifact changed in transit: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Disposition") != `attachment; filename="http.json"` || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatal("evidence must be downloaded, not rendered", w.Header())
	}
}

func TestOffensiveDiagnosticAuthenticatedObservationKeepsPrincipalContext(t *testing.T) {
	var run offensiveDiagnosticRun
	if err := json.Unmarshal([]byte(`{"id":"ce386a3f-a6fc-46a5-88c2-67c4c474fb59","target_url":"https://example.invalid/api","goal":"검증 목표","auth_context":"provided_bearer","observations":[{"id":"o1","kind":"endpoint","url":"https://example.invalid/api/items","method":"GET","status_code":200,"confidence":"observed","auth_context":"provided_bearer","evidence_ref":"http.json"}]}`), &run); err != nil {
		t.Fatal(err)
	}
	goal, err := diagnosticGoal(run)
	if err != nil {
		t.Fatal(err)
	}
	if run.AuthContext != "provided_bearer" || run.Observations[0].AuthContext != "provided_bearer" || strings.Count(goal, `"auth_context":"provided_bearer"`) != 1 || !strings.Contains(goal, "anonymous follow-up requests are not the same principal") {
		t.Fatal("authenticated discovery lost principal context during native task handoff")
	}
}

func TestOffensiveDiagnosticGoalUsesCompactEvidenceIndex(t *testing.T) {
	run := offensiveDiagnosticRun{ID: uuid.NewString(), TargetURL: "http://example.invalid/", Goal: "문서 노출 경로 조사"}
	for i := 0; i < 35; i++ {
		run.Observations = append(run.Observations, offensiveDiagnosticObservation{
			ID: fmt.Sprintf("o%d", i), URL: fmt.Sprintf("http://example.invalid/ftp/item-%d", i),
			Method: "GET", Confidence: "observed", EvidenceRef: fmt.Sprintf("http-%d.json", i),
			Summary: strings.Repeat("large observed response summary ", 20),
		})
	}
	for i := 0; i < 8; i++ {
		run.AttackPaths = append(run.AttackPaths, offensiveDiagnosticPath{
			ID: fmt.Sprintf("p%d", i), TargetURL: fmt.Sprintf("http://example.invalid/ftp/item-%d", i),
			EvidenceRefs: []string{fmt.Sprintf("http-%d.json", i)},
		})
	}
	goal, err := diagnosticGoal(run)
	if err != nil {
		t.Fatal(err)
	}
	if len(goal) > 7000 || !strings.Contains(goal, `"observation_count":35`) || !strings.Contains(goal, "http-0.json") || strings.Contains(goal, "large observed response summary") {
		t.Fatalf("follow-up goal repeated full evidence (%d bytes)", len(goal))
	}
}

func TestOffensiveDiagnosticAPIOperationInventoryIsScopedAndUnverified(t *testing.T) {
	run := offensiveDiagnosticRun{
		ID: uuid.NewString(), TargetURL: "http://example.invalid/", Goal: "API 진단 근거 확인",
		Coverage: &offensiveDiagnosticCoverage{
			ObservedGETURLs: 2, DocumentedOperations: 3,
			UnverifiedDocumentedOperations: 2, Limits: []string{"url_budget_reached"},
		},
		APIOperations: []offensiveDiagnosticAPIOperation{
			{Method: "GET", Path: "/api/items", URL: "http://example.invalid/api/items", SourceURL: "http://example.invalid/openapi.json", Verification: "observed_get"},
			{Method: "POST", Path: "/api/items", URL: "http://example.invalid/api/items", SourceURL: "http://example.invalid/openapi.json", Verification: "documented_unverified"},
			{Method: "GET", Path: "/api/items/{id}", URL: "", SourceURL: "http://example.invalid/openapi.json", Verification: "documented_unverified"},
		},
	}
	goal, err := diagnosticGoal(run)
	if err != nil || !strings.Contains(goal, `"api_operation_count":3`) || !strings.Contains(goal, `"exhaustive":false`) || !strings.Contains(goal, "Operations other than GET must not be executed") {
		t.Fatalf("API inventory lost its unverified scope/coverage: %v %s", err, goal)
	}
	run.APIOperations[1].URL = "http://other.invalid/api/items"
	if _, err := diagnosticGoal(run); err == nil {
		t.Fatal("out-of-scope documented operation accepted")
	}
	run.APIOperations[1].URL = "http://example.invalid/api/items"
	run.APIOperations[2].Verification = "observed_get"
	if _, err := diagnosticGoal(run); err == nil {
		t.Fatal("templated URL with no request accepted as observed")
	}
}

func TestOffensiveDiagnosticBootstrapSelectsObservedRankedPath(t *testing.T) {
	run := offensiveDiagnosticRun{TargetURL: "http://example.invalid/"}
	run.Observations = []offensiveDiagnosticObservation{
		{URL: "http://example.invalid/guess", Confidence: "inferred"},
		{URL: "http://example.invalid/shell", Confidence: "observed", Sources: []string{"same_as_scope_root"}},
		{URL: "http://example.invalid/first", Confidence: "observed"},
		{URL: "http://example.invalid/second", Confidence: "observed"},
	}
	run.AttackPaths = []offensiveDiagnosticPath{
		{ID: "guess", TargetURL: "http://example.invalid/guess"},
		{ID: "shell", TargetURL: "http://example.invalid/shell"},
		{ID: "first", TargetURL: "http://example.invalid/first"},
		{ID: "second", TargetURL: "http://example.invalid/second"},
	}
	if got := diagnosticTopObservedPath(run); got == nil || got.ID != "first" {
		t.Fatalf("ranked observed path = %+v", got)
	}
	run.AttackPaths[2].Status = "rejected"
	if got := diagnosticTopObservedPath(run); got == nil || got.ID != "second" {
		t.Fatalf("rejected path was selected: %+v", got)
	}
}

func TestOffensiveDiagnosticBootstrapGroupsDistinctObservedPaths(t *testing.T) {
	run := offensiveDiagnosticRun{TargetURL: "http://example.invalid/"}
	run.Observations = []offensiveDiagnosticObservation{
		{URL: "http://example.invalid/guess", Confidence: "inferred"},
		{URL: "http://example.invalid/spa-shell", Confidence: "observed", Sources: []string{"same_as_scope_root"}},
		{URL: "http://example.invalid/api/a", Confidence: "observed"},
		{URL: "http://example.invalid/api/b", Confidence: "observed"},
		{URL: "http://example.invalid/api/c", Confidence: "observed"},
		{URL: "http://example.invalid/api/d", Confidence: "observed"},
	}
	run.AttackPaths = []offensiveDiagnosticPath{
		{ID: "guess", TargetURL: "http://example.invalid/guess"},
		{ID: "shell", TargetURL: "http://example.invalid/spa-shell"},
		{ID: "a", TargetURL: "http://example.invalid/api/a"},
		{ID: "a-duplicate", TargetURL: "http://example.invalid/api/a"},
		{ID: "b", TargetURL: "http://example.invalid/api/b"},
		{ID: "c", TargetURL: "http://example.invalid/api/c"},
		{ID: "d", TargetURL: "http://example.invalid/api/d"},
	}
	paths := diagnosticTopObservedPaths(run, 3)
	if len(paths) != 3 || paths[0].ID != "a" || paths[1].ID != "b" || paths[2].ID != "c" {
		t.Fatalf("selected paths = %+v", paths)
	}
	if got := diagnosticTopObservedPaths(run, 1); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("single bounded selection = %+v", got)
	}
}

func TestOffensiveDiagnosticBootstrapPrefersObservedGoalAlignedChild(t *testing.T) {
	ok, forbidden := 200, 403
	base := "https://example.invalid/files"
	run := offensiveDiagnosticRun{TargetURL: "https://example.invalid/", Goal: "Find exposed documents"}
	run.Observations = []offensiveDiagnosticObservation{
		{URL: base, Confidence: "observed", StatusCode: &ok},
		{URL: base + "/unobserved.txt", Confidence: "inferred", StatusCode: &ok},
		{URL: base + "/private.txt", Confidence: "observed", StatusCode: &forbidden},
		{URL: base + "/ordinary", Confidence: "observed", StatusCode: &ok},
		{URL: base + "/report.pdf", Confidence: "observed", StatusCode: &ok},
	}
	priority := []string{"goal-relevant", "HTTP response"}
	run.AttackPaths = []offensiveDiagnosticPath{
		{ID: "directory", TargetURL: base, PriorityBasis: priority},
		{ID: "unobserved", TargetURL: base + "/unobserved.txt", PriorityBasis: priority},
		{ID: "forbidden", TargetURL: base + "/private.txt", PriorityBasis: priority},
		{ID: "unrelated", TargetURL: base + "/ordinary", PriorityBasis: []string{"HTTP response"}},
		{ID: "document", TargetURL: base + "/report.pdf", PriorityBasis: priority},
	}
	if got := diagnosticTopObservedPath(run); got == nil || got.ID != "document" {
		t.Fatalf("expected observed goal-aligned 200 child, got %+v", got)
	}
	run.AttackPaths[0].CandidateIDs = []string{"scanner-candidate"}
	if got := diagnosticTopObservedPath(run); got == nil || got.ID != "directory" {
		t.Fatalf("ranked scanner candidate should retain priority, got %+v", got)
	}
}

func TestDiagnosticURLChildRequiresSameOriginAndPathBoundary(t *testing.T) {
	parent := "https://example.invalid/files"
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://example.invalid/files/report.pdf", true},
		{"https://example.invalid/files-extra/report.pdf", false},
		{"https://example.invalid.evil/files/report.pdf", false},
		{"http://example.invalid/files/report.pdf", false},
		{"https://example.invalid/files", false},
	} {
		if got := diagnosticURLChild(parent, tc.url); got != tc.want {
			t.Errorf("diagnosticURLChild(%q, %q) = %v, want %v", parent, tc.url, got, tc.want)
		}
	}
}

func TestOffensiveDiagnosticBindingStringTaskIDAndNoModel(t *testing.T) {
	id := uuid.NewString()
	var bodies []map[string]any
	_, _ = offensiveProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/diagnostics/runs/"+id+"/followup" {
			t.Error("unexpected bind route", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		taskID, ok := body["task_id"].(string)
		if !ok || (taskID != "" && taskID != "17") {
			http.Error(w, `{"error":"invalid string task ID"}`, 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "followup": body})
	}))
	cfg, _ := loadOffensiveConfig()
	s := &Server{}
	for _, input := range []struct{ status, taskID, message string }{{"running", "17", ""}, {"needs_model", "", "configure model"}} {
		_, code, err := s.bindDiagnosticFollowup(t.Context(), cfg, id, input.status, input.taskID, input.message)
		if err != nil || code != 200 {
			t.Fatal(code, err)
		}
	}
	if len(bodies) != 2 || bodies[0]["task_id"] != "17" || bodies[1]["task_id"] != "" {
		t.Fatal(bodies)
	}
}

func TestOffensiveDiagnosticFollowupRebindsExistingTaskWithoutDuplication(t *testing.T) {
	id := uuid.NewString()
	var binds atomic.Int32
	_, _ = offensiveProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(offensiveDiagnosticRun{ID: id, Status: "completed", TargetURL: "http://example.invalid/"})
			return
		}
		if binds.Add(1) == 1 {
			w.WriteHeader(503)
			_, _ = io.WriteString(w, `{"error":"association temporarily unavailable"}`)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["task_id"] != "17" || body["status"] != "running" {
			t.Error(body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "followup": body})
	}))
	task := &Task{ID: "17", Description: diagnosticMarker(id) + " existing native task"}
	// The empty DB is intentional: the recovery path must not create a task,
	// import evidence or call a model once the durable marker is found.
	s := &Server{m: &Manager{pg: &db.DB{}, tasks: map[string]*Task{"17": task}}, engine: &Engine{}}
	cfg, _ := loadOffensiveConfig()
	_, code, err := s.ensureDiagnosticFollowup(t.Context(), cfg, id, nil, 300, true)
	if err == nil || code != 503 {
		t.Fatal("expected failed association", code, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.offensiveDiagnosticMu.Lock()
			defer s.offensiveDiagnosticMu.Unlock()
			_, code, err := s.ensureDiagnosticFollowup(context.Background(), cfg, id, nil, 300, true)
			if err != nil || code != 200 {
				t.Errorf("retry = %d %v", code, err)
			}
		}()
	}
	wg.Wait()
	if len(s.m.List()) != 1 || binds.Load() != 5 {
		t.Fatal("duplicate follow-up task or missing recovery", len(s.m.List()), binds.Load())
	}
	if findDiagnosticTask([]*Task{{Description: "prefix " + diagnosticMarker(id) + " decoy"}}, id) != nil {
		t.Fatal("non-marker description matched")
	}
}

func TestOffensiveDiagnosticFollowupRejectsUnfinishedCancelledOrMissingTask(t *testing.T) {
	id := uuid.NewString()
	run := offensiveDiagnosticRun{ID: id, Status: "running", TargetURL: "http://example.invalid/"}
	var writes atomic.Int32
	_, _ = offensiveProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes.Add(1)
		}
		_ = json.NewEncoder(w).Encode(run)
	}))
	s := &Server{m: &Manager{pg: &db.DB{}, tasks: map[string]*Task{}}, engine: &Engine{}}
	cfg, _ := loadOffensiveConfig()
	for _, status := range []string{"queued", "running", "failed", "cancelled", "interrupted"} {
		run.Status = status
		_, code, err := s.ensureDiagnosticFollowup(t.Context(), cfg, id, nil, 300, true)
		if code != 409 || err == nil {
			t.Fatalf("%s = %d %v", status, code, err)
		}
	}
	run.Status = "partial"
	run.Followup.Status = "cancelled"
	if _, code, err := s.ensureDiagnosticFollowup(t.Context(), cfg, id, nil, 300, true); code != 409 || err == nil {
		t.Fatal(code, err)
	}
	run.Followup.Status = "running"
	run.Followup.TaskID = "999"
	if _, code, err := s.ensureDiagnosticFollowup(t.Context(), cfg, id, nil, 300, true); code != 409 || err == nil {
		t.Fatal(code, err)
	}
	if writes.Load() != 0 || len(s.m.List()) != 0 {
		t.Fatal("invalid follow-up mutated state")
	}
}

func diagnosticManagerFixture(t *testing.T) *Manager {
	t.Helper()
	if os.Getenv("ARTEX_PG_DSN") == "" {
		t.Skip("isolated ARTEX_PG_DSN required")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestOffensiveDiagnosticImportsObservationsWithoutConfirmingCandidates(t *testing.T) {
	m := diagnosticManagerFixture(t)
	id := uuid.NewString()
	task, err := m.CreateTaskWithOptions(diagnosticMarker(id)+" evidence test", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{DeleteAssets: true, DeleteFindings: true}) })
	// A second exploration deliberately separates the two ID spaces so asset
	// attribution cannot accidentally pass because their sequences coincide.
	other, err := m.CreateTaskWithOptions("diagnostic auxiliary exploration", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(other.ID, DeleteTaskOptions{DeleteAssets: true, DeleteFindings: true}) })
	originalExpID := task.ExpID
	task.ExpID = other.ExpID
	defer func() { task.ExpID = originalExpID }()
	base := "http://" + strings.ReplaceAll(id, "-", "") + ".invalid/api"
	status := 200
	run := offensiveDiagnosticRun{ID: id, TargetURL: base, Observations: []offensiveDiagnosticObservation{
		{ID: "observed", Kind: "service", URL: base, Method: "GET", Confidence: "observed", StatusCode: &status, EvidenceRef: "http.json"},
		{ID: "inferred", Kind: "endpoint", URL: base + "/items", Method: "GET", Parameters: []string{"id"}, Confidence: "inferred", EvidenceRef: "links.json"},
	}, Candidates: []offensiveDiagnosticCandidate{{ID: "candidate", URL: base + "/items", Title: "scanner candidate", Verification: "candidate", EvidenceRefs: []string{"nuclei.json"}}},
		APIOperations: []offensiveDiagnosticAPIOperation{{Method: "POST", Path: "/api/items", URL: base + "/items", SourceURL: base + "/openapi.json", EvidenceRef: "openapi.json", Verification: "documented_unverified"}},
	}
	s := &Server{m: m}
	if err := s.importDiagnosticEvidence(task, run); err != nil {
		t.Fatal(err)
	}
	nodes, err := task.Store.Nodes(100)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	inventoryHint := false
	for _, n := range nodes {
		if n.Origin == "diagnostic-discovery" || n.Origin == "diagnostic-tool" || n.Origin == "diagnostic-api-inventory" {
			counts[n.Kind]++
			if n.Origin == "diagnostic-api-inventory" {
				var payload map[string]any
				if json.Unmarshal(n.Payload, &payload) == nil && payload["verification"] == "documented_unverified" && payload["operation_count"] == float64(1) {
					inventoryHint = true
				}
			}
			if n.Kind == "hint" && n.State != "active" {
				t.Errorf("candidate state=%s", n.State)
			}
			if n.Kind == "hint" && n.Origin == "diagnostic-discovery" {
				var payload map[string]any
				if json.Unmarshal(n.Payload, &payload) != nil || payload["text"] != payload["summary"] {
					t.Error("inferred observation hint is missing graph-overview text")
				}
			}
		}
	}
	if counts["fact"] != 1 || counts["hint"] != 3 || counts["finding"] != 0 || !inventoryHint {
		t.Fatalf("candidates promoted or observations lost: %v", counts)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	for _, o := range run.Observations {
		var attributed bool
		if err := m.pg.QueryRow(`SELECT $2 = ANY(task_ids) FROM assets WHERE url=$1 AND type=$3`, o.URL, taskID, o.Kind).Scan(&attributed); err != nil || !attributed {
			t.Errorf("asset %s attributed to exploration instead of task: %v %v", o.URL, attributed, err)
		}
	}
	var params string
	if err := m.pg.QueryRow(`SELECT array_to_json(params)::text FROM assets WHERE url=$1 AND type='endpoint'`, base+"/items").Scan(&params); err != nil {
		t.Fatal(err)
	}
	var decodedParams []map[string]any
	if json.Unmarshal([]byte(params), &decodedParams) != nil || len(decodedParams) != 1 || decodedParams[0]["name"] != "id" || decodedParams[0]["location"] != "query" {
		t.Fatalf("query parameter location is missing: %s", params)
	}
	rows, _, err := m.pg.ListFindingsPage(db.FindingFilter{TaskID: task.ID}, 1, 100)
	if err != nil || len(rows) != 0 {
		t.Fatal("discovery imported confirmed findings", len(rows), err)
	}
}

func TestOffensiveDiagnosticBootstrapPersistsGoalScopeAndEvidenceLineage(t *testing.T) {
	m := diagnosticManagerFixture(t)
	id := uuid.NewString()
	base := "http://" + strings.ReplaceAll(id, "-", "") + ".invalid/"
	run := offensiveDiagnosticRun{
		ID: id, TargetURL: base, ScopeURLs: []string{base}, Goal: "익명 문서 노출을 근거로 확인하세요",
		Observations: []offensiveDiagnosticObservation{
			{ID: "observed", Kind: "endpoint", URL: base + "ftp", Method: "GET", Confidence: "observed", EvidenceRef: "http.json"},
			{ID: "observed-2", Kind: "endpoint", URL: base + "api", Method: "GET", Confidence: "observed", EvidenceRef: "api.json"},
		},
		AttackPaths: []offensiveDiagnosticPath{
			{ID: "ranked-path", TargetURL: base + "ftp", Status: "verification_required", EvidenceRefs: []string{"http.json"}},
			{ID: "second-path", TargetURL: base + "api", Status: "verification_required", EvidenceRefs: []string{"api.json"}},
		},
	}
	task, err := m.CreateTaskWithOptions(diagnosticMarker(id)+" bootstrap test", "bounded internal task goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{DeleteAssets: true, DeleteFindings: true}) })
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	preexistingAssetID, err := m.Assets().UpsertEndpoint(db.UpsertEndpointReq{URL: base + "ftp", Method: "GET", TaskID: taskID})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}
	if err := s.importDiagnosticEvidence(task, run); err != nil {
		t.Fatal(err)
	}
	if err := s.bootstrapDiagnosticFollowup(task, run); err != nil {
		t.Fatal(err)
	}
	if got, ok := diagnosticBootstrapGoal(task); !ok || got != run.Goal {
		t.Fatalf("single saved goal = %q, %v", got, ok)
	}
	goals, err := task.Store.ListByKind(db.KindGoal, 10)
	if err != nil || len(goals) != 1 {
		t.Fatalf("expected one saved goal, got %d, %v", len(goals), err)
	}
	constraints, err := task.Store.ListConstraints()
	if err != nil || len(constraints) != 3 || !strings.Contains(constraints[0].Text, base) || !strings.Contains(constraints[1].Text, "GET 또는 HEAD") {
		t.Fatalf("scope/method constraints = %+v, %v", constraints, err)
	}
	intents, err := task.Store.ListByKind(db.KindIntent, 10)
	if err != nil || len(intents) != 1 || intents[0].State != "open" || intents[0].Priority != 9 || intents[0].Origin != "diagnostic-bootstrap" {
		t.Fatalf("seeded intent = %+v, %v", intents, err)
	}
	var intentPayload map[string]any
	if err := json.Unmarshal(intents[0].Payload, &intentPayload); err != nil || intentPayload["attack_path_id"] != "ranked-path" || !strings.Contains(intentPayload["summary"].(string), base+"ftp") || !strings.Contains(intentPayload["summary"].(string), "무인증 GET으로 응답 본문과 상태를 먼저 확인") {
		t.Fatalf("seed intent lost ranked path: %+v, %v", intentPayload, err)
	}
	if ids, ok := intentPayload["attack_path_ids"].([]any); !ok || len(ids) != 2 || ids[0] != "ranked-path" || ids[1] != "second-path" {
		t.Fatalf("one bounded intent did not retain both observed paths: %+v", intentPayload)
	}
	var intentAssetPayload struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(intents[0].Payload, &intentAssetPayload); err != nil || len(intentAssetPayload.AssetIDs) != 2 || !slices.Contains(intentAssetPayload.AssetIDs, preexistingAssetID) {
		t.Fatalf("seed intent lost imported asset id %d: %+v, %v", preexistingAssetID, intentAssetPayload, err)
	}
	var anchorCount int
	if err := m.pg.QueryRow(`SELECT count(*) FROM exploration_anchors WHERE node_id=$1 AND asset_id=$2`, intents[0].ID, preexistingAssetID).Scan(&anchorCount); err != nil || anchorCount != 1 {
		t.Fatalf("seed intent asset anchor count=%d, %v", anchorCount, err)
	}
	origin, err := task.Store.OriginFactID()
	if err != nil || origin <= 0 {
		t.Fatal("origin fact missing", err)
	}
	observedFact, importedAssetIDs, err := diagnosticObservedFact(task, base+"ftp")
	if err != nil || observedFact <= 0 || len(importedAssetIDs) != 1 || importedAssetIDs[0] != preexistingAssetID {
		t.Fatal("observed parent fact missing", err)
	}
	secondObservedFact, secondAssetIDs, err := diagnosticObservedFact(task, base+"api")
	if err != nil || secondObservedFact <= 0 || len(secondAssetIDs) != 1 || !slices.Contains(intentAssetPayload.AssetIDs, secondAssetIDs[0]) {
		t.Fatal("second observed parent fact missing", err)
	}
	edges, err := task.Store.Edges(100)
	if err != nil {
		t.Fatal(err)
	}
	want := map[db.Edge]bool{
		{From: origin, Rel: db.RelSpawns, To: goals[0].ID}:                    false,
		{From: origin, Rel: db.RelDerivedFrom, To: intents[0].ID}:             false,
		{From: observedFact, Rel: db.RelDerivedFrom, To: intents[0].ID}:       false,
		{From: secondObservedFact, Rel: db.RelDerivedFrom, To: intents[0].ID}: false,
	}
	for _, edge := range edges {
		if _, ok := want[edge]; ok {
			want[edge] = true
		}
	}
	for edge, found := range want {
		if !found {
			t.Fatalf("missing lineage edge: %+v", edge)
		}
	}
}

func TestOffensiveDiagnosticCancelPausesNativeTaskBeforeRunnerFailure(t *testing.T) {
	m := diagnosticManagerFixture(t)
	id := uuid.NewString()
	task, err := m.CreateTaskWithOptions(diagnosticMarker(id)+" cancel test", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	s, request := offensiveProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/diagnostics/runs/"+id+"/cancel" {
			t.Error(r.Method, r.URL.Path)
		}
		if !task.lifecycleSnapshot().Paused {
			t.Error("runner cancellation started before native task was paused")
		}
		w.WriteHeader(503)
		_, _ = io.WriteString(w, `{"error":"runner temporarily unavailable"}`)
	}))
	admission := newAdmissionTestServer(m, func(*Task) bool { return false })
	s.m, s.engine, s.ctx = m, admission.engine, admission.ctx
	w := request("POST", "/api/offensive/diagnostics/runs/"+id+"/cancel", `{}`)
	if w.Code != 503 || !task.lifecycleSnapshot().Paused {
		t.Fatal("cancel lost during runner failure", w.Code, w.Body.String())
	}
	if got := diagnosticFollowupStatus(task); got != "cancelled" {
		t.Fatal(got)
	}
}

func TestOffensiveDiagnosticTaskResultUsesTaskIDForFindings(t *testing.T) {
	m := diagnosticManagerFixture(t)
	id := uuid.NewString()
	task, err := m.CreateTaskWithOptions(diagnosticMarker(id)+" result test", "goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{DeleteFindings: true}) })
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	fid, err := m.pg.AddFinding(taskID, 0, "test", "diagnostic finding", "low", "confirmed evidence", "test-only proof", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	originalExpID := task.ExpID
	task.ExpID = originalExpID + 1000000
	defer func() { task.ExpID = originalExpID }()
	value := map[string]any{"id": id}
	(&Server{m: m}).enrichDiagnosticTaskResult(value)
	follow := value["followup"].(map[string]any)
	result := follow["result"].(map[string]any)
	findings := result["findings"].([]map[string]any)
	if len(findings) != 1 || fmt.Sprint(findings[0]["id"]) != strconv.FormatInt(fid, 10) {
		t.Fatalf("finding associated with task omitted: %+v", findings)
	}
	if result["findings_total"] != 1 || result["findings_complete"] != true {
		t.Fatalf("finding count/completeness was lost: %+v", result)
	}
}

func TestOffensiveDiagnosticRunListUsesCurrentTaskStatus(t *testing.T) {
	id := uuid.NewString()
	otherID := uuid.NewString()
	task := &Task{ID: "42", Description: diagnosticMarker(id) + " status test", Status: "timeout"}
	s, request := offensiveProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/diagnostics/runs" {
			t.Errorf("unexpected runner request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"runs": []any{
			map[string]any{"id": id, "followup": map[string]any{"status": "running", "task_id": "old", "error": "stale runner error"}},
			map[string]any{"id": otherID, "followup": map[string]any{"status": "pending"}},
		}})
	}))
	s.m = &Manager{tasks: map[string]*Task{task.ID: task}}
	check := func(wantFollowup, wantTask string, wantError bool) {
		t.Helper()
		w := request("GET", "/api/offensive/diagnostics/runs", "")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var body struct {
			Runs []struct {
				ID       string         `json:"id"`
				Followup map[string]any `json:"followup"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Runs) != 2 || body.Runs[0].Followup["status"] != wantFollowup || body.Runs[0].Followup["task_status"] != wantTask || body.Runs[0].Followup["task_id"] != task.ID {
			t.Fatalf("task status not refreshed: %+v", body.Runs)
		}
		_, hasError := body.Runs[0].Followup["error"]
		if hasError != wantError || body.Runs[0].Followup["result"] != nil {
			t.Fatalf("unexpected list enrichment: %+v", body.Runs[0].Followup)
		}
		if body.Runs[1].Followup["status"] != "pending" || body.Runs[1].Followup["task_status"] != nil {
			t.Fatalf("unrelated run was modified: %+v", body.Runs[1].Followup)
		}
	}
	check("failed", "timeout", true)
	task.updateLifecycle(func(life *taskLifecycleState) { life.Status, life.Paused = "", true })
	check("cancelled", "paused", false)
}
