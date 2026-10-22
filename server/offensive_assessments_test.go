package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
)

const offensiveTestToken = "offensive-runner-private-test-token"

func offensiveProxyFixture(t *testing.T, upstream http.Handler) (*Server, func(string, string, string) *httptest.ResponseRecorder) {
	return offensiveFixture(t, upstream, false)
}

// Legacy helpers remain tested for reading historical evidence; production POST
// routes are separately asserted to return 410 by diagnostic route tests.
func offensiveLegacyProxyFixture(t *testing.T, upstream http.Handler) (*Server, func(string, string, string) *httptest.ResponseRecorder) {
	return offensiveFixture(t, upstream, true)
}

func offensiveLegacyHandler(s *Server) http.Handler {
	mux := http.NewServeMux()
	for _, path := range []string{"/catalog", "/runs", "/runs/{id}", "/runs/{id}/artifacts/{name}"} {
		mux.HandleFunc("GET /api/offensive"+path, func(w http.ResponseWriter, r *http.Request) { s.proxyOffensiveAssessment(w, r, path) })
	}
	mux.HandleFunc("POST /api/offensive/runs", func(w http.ResponseWriter, r *http.Request) { s.proxyOffensiveAssessment(w, r, "/runs") })
	mux.HandleFunc("POST /api/offensive/runs/{id}/review", s.reviewOffensiveAssessment)
	mux.HandleFunc("GET /api/offensive/runs/{id}/candidate-review", s.getOffensiveCandidateReview)
	mux.HandleFunc("POST /api/offensive/runs/{id}/candidate-review", s.startOffensiveCandidateReview)
	mux.HandleFunc("POST /api/offensive/runs/{id}/candidate-review/cancel", s.cancelOffensiveCandidateReview)
	mux.HandleFunc("POST /api/offensive/targets", s.uploadOffensiveTarget)
	return s.requireAuth(mux)
}

// Exercise the retired diagnostic implementation in isolation. Production's
// Server.Handler deliberately exposes only the original Tasks API.
func offensiveDiagnosticHandler(s *Server) http.Handler {
	mux := http.NewServeMux()
	s.registerOffensiveDiagnostics(mux)
	return s.requireAuth(mux)
}

func offensiveFixture(t *testing.T, upstream http.Handler, legacy bool) (*Server, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	runner := httptest.NewServer(upstream)
	t.Cleanup(runner.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(offensiveTestToken), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_OFFENSIVE_URL", runner.URL)
	t.Setenv("ARTEX_OFFENSIVE_TOKEN_FILE", tokenFile)
	s := &Server{jwtKey: []byte("offensive-test-jwt-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := offensiveDiagnosticHandler(s)
	if legacy {
		handler = offensiveLegacyHandler(s)
	}
	return s, func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Cookie", "private-browser-cookie")
		r.Header.Set("X-Private-Browser-Header", "never-forward")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
}

func TestOffensiveAuthenticationAndUnavailable(t *testing.T) {
	t.Setenv("ARTEX_OFFENSIVE_URL", "")
	t.Setenv("ARTEX_OFFENSIVE_TOKEN_FILE", "")
	s := &Server{jwtKey: []byte("offensive-disabled-jwt-key")}
	handler := s.Handler()
	token, _ := signJWT(s.jwtKey)
	id := uuid.NewString()
	for _, route := range []struct{ method, path, body string }{
		{"GET", "/catalog", ""}, {"GET", "/runs", ""},
		{"POST", "/targets", ""},
		{"POST", "/runs", `{"kind":"api","target_id":"crapi"}`},
		{"GET", "/runs/" + id, ""}, {"POST", "/runs/" + id + "/review", `{}`},
		{"GET", "/runs/" + id + "/artifacts/report.json", ""},
	} {
		path := "/api/offensive" + route.path
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(route.method, path, strings.NewReader(route.body)))
		if w.Code != 401 {
			t.Fatalf("%s unauthenticated = %d", path, w.Code)
		}
		r := httptest.NewRequest(route.method, path, strings.NewReader(route.body))
		r.Header.Set("Authorization", "Bearer "+token)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := 410
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s = %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestOffensiveScopeValidationAndCredentialIsolation(t *testing.T) {
	var calls atomic.Int32
	id := uuid.NewString()
	_, request := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+offensiveTestToken || r.Header.Get("Cookie") != "" || r.Header.Get("X-Private-Browser-Header") != "" {
			t.Error("credential isolation failed")
		}
		if r.Method == "POST" {
			raw, _ := io.ReadAll(r.Body)
			if string(raw) != `{"kind":"api","target_id":"crapi"}` {
				t.Error("unexpected command", string(raw))
			}
		}
		w.Header().Set("Set-Cookie", "private-upstream-cookie")
		json.NewEncoder(w).Encode(map[string]any{"path": r.URL.Path, "note": offensiveTestToken})
	}))
	for _, req := range []struct{ method, path, body string }{
		{"POST", "/runs", `{"kind":"api","target_id":"benchmark"}`},
		{"POST", "/runs", `{"kind":"api","target_id":"crapi","url":"https://external.invalid"}`},
		{"POST", "/runs", `{"kind":"api","target_id":"crapi"}{}`},
		{"POST", "/runs", "null"},
		{"GET", "/catalog?url=external", ""},
		{"GET", "/runs/invalid", ""},
		{"GET", "/runs/" + id + "/artifacts/a..json", ""},
		{"POST", "/runs/" + id + "/review", `{"command":"arbitrary"}`},
	} {
		w := request(req.method, "/api/offensive"+req.path, req.body)
		if w.Code != 400 {
			t.Fatalf("%s = %d %s", req.path, w.Code, w.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached runner")
	}
	w := request("POST", "/api/offensive/runs", `{"kind":"api","target_id":"crapi"}`)
	if w.Code != 200 || calls.Load() != 1 || strings.Contains(w.Body.String(), offensiveTestToken) || w.Header().Get("Set-Cookie") != "" || !strings.Contains(w.Body.String(), `"path":"/runs"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestOffensiveArtifactAndRedirectHandling(t *testing.T) {
	id := uuid.NewString()
	_, request := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/redirect.json"):
			w.Header().Set("Location", "http://outside.invalid/private")
			w.WriteHeader(302)
		case strings.HasSuffix(r.URL.Path, "/secret.json"):
			io.WriteString(w, offensiveTestToken)
		case strings.HasSuffix(r.URL.Path, "/missing.json"):
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"not found"}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<script>untrusted evidence</script>")
		}
	}))
	base := "/api/offensive/runs/" + id + "/artifacts/"
	w := request("GET", base+"report.json", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/octet-stream" || w.Header().Get("Content-Disposition") != `attachment; filename="report.json"` || !strings.Contains(w.Body.String(), "untrusted evidence") {
		t.Fatal(w.Code, w.Header(), w.Body.String())
	}
	for _, name := range []string{"redirect.json", "secret.json"} {
		w = request("GET", base+name, "")
		if w.Code != 502 || strings.Contains(w.Body.String(), offensiveTestToken) {
			t.Fatal(name, w.Code, w.Body.String())
		}
	}
	w = request("GET", base+"missing.json", "")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "not found") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestOffensiveInvalidConfigurationAndMalformedResponse(t *testing.T) {
	_, request := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"ok":true}{"extra":true}`) }))
	w := request("GET", "/api/offensive/catalog", "")
	if w.Code != 502 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{"file:///tmp/runner", "http://user:pass@runner", "http://runner/private", "http://runner?cmd=1"} {
		t.Setenv("ARTEX_OFFENSIVE_URL", bad)
		cfg, configured := loadOffensiveConfig()
		if cfg != nil || !configured {
			t.Fatal("unsafe configuration accepted", bad)
		}
	}
}

func TestOffensiveReviewGoalsSeparateStaticAndRuntimeEvidence(t *testing.T) {
	id := uuid.NewString()
	for _, target := range []struct{ kind, id, skill string }{{"api", "crapi", "api-assessment"}, {"source", "benchmark", "source-assessment"}} {
		description, goal, seed, err := offensiveReviewGoal(offensiveRun{ID: id, Kind: target.kind, TargetID: target.id})
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{target.skill + "/SKILL.md", "/app/data/offensive/runs/" + id + "/report.json", "NOT confirmed", "report_finding", "600-second", "untrusted evidence"} {
			if !strings.Contains(goal, text) {
				t.Fatal("missing review requirement", target.kind, text)
			}
		}
		if !strings.HasPrefix(description, offensiveReviewMarker(id)) {
			t.Fatal(description)
		}
		if target.kind == "source" {
			if !strings.Contains(goal, "runtime exploitation was not tested") || !strings.Contains(goal, "Do not consult expectedresults.csv") || strings.Contains(seed, "http") {
				t.Fatal(goal, seed)
			}
		} else if seed != "http://crapi-web:80" || !strings.Contains(goal, "30 additional HTTP requests") {
			t.Fatal(goal, seed)
		}
	}
	if _, _, _, err := offensiveReviewGoal(offensiveRun{ID: id, Kind: "api", TargetID: "external"}); err == nil {
		t.Fatal("unsupported target")
	}
}

func TestOffensiveReviewRejectsIncompleteRunAndReusesAttachedTask(t *testing.T) {
	id := uuid.NewString()
	status := "running"
	s, request := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("unexpected task mutation")
		}
		json.NewEncoder(w).Encode(offensiveRun{ID: id, Kind: "source", TargetID: "benchmark", Status: status, TaskID: "17"})
	}))
	path := "/api/offensive/runs/" + id + "/review"
	w := request("POST", path, `{}`)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	status = "completed"
	task := &Task{ID: "17", Description: offensiveReviewMarker(id) + " review"}
	s.m = &Manager{tasks: map[string]*Task{"17": task}}
	s.engine = &Engine{}
	for i := 0; i < 2; i++ {
		w = request("POST", path, `{}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"task_id":"17"`) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestOffensiveReviewRetryAfterAssociationFailureDoesNotDuplicateTask(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	id := uuid.NewString()
	var binds atomic.Int32
	var mu sync.Mutex
	bound := ""
	s, request := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			if binds.Add(1) == 1 {
				w.WriteHeader(503)
				io.WriteString(w, `{"error":"temporary"}`)
				return
			}
			var req struct {
				TaskID string `json:"task_id"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			bound = req.TaskID
		}
		json.NewEncoder(w).Encode(offensiveRun{ID: id, Kind: "source", TargetID: "benchmark", Status: "completed", TaskID: bound})
	}))
	admission := newAdmissionTestServer(m, func(*Task) bool { return false })
	s.m, s.engine, s.ctx = m, admission.engine, admission.ctx
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(true, 1); err != nil {
		t.Fatal(err)
	}
	before := len(m.List())
	defer func() {
		if task := findOffensiveReviewTask(m.List(), id); task != nil {
			_, _ = m.DeleteTask(task.ID, DeleteTaskOptions{})
		}
	}()
	path := "/api/offensive/runs/" + id + "/review"
	w := request("POST", path, `{}`)
	if w.Code != 502 || !strings.Contains(w.Body.String(), "task_id") {
		t.Fatal(w.Code, w.Body.String())
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := request("POST", path, `{}`)
			if response.Code != 200 && response.Code != 201 {
				t.Error(response.Code, response.Body.String())
			}
		}()
	}
	wg.Wait()
	if len(m.List()) != before+1 || binds.Load() != 2 {
		t.Fatal("duplicate task or association", len(m.List())-before, binds.Load())
	}
	task := findOffensiveReviewTask(m.List(), id)
	if task == nil || task.TimeoutSeconds != 600 {
		t.Fatal("missing bounded review task")
	}
}

type offensiveUploadPart struct {
	key, filename string
	content       []byte
}

func offensiveMultipartRequest(t *testing.T, s *Server, parts []offensiveUploadPart) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, part := range parts {
		var output io.Writer
		var err error
		if part.filename == "" {
			output, err = writer.CreateFormField(part.key)
		} else {
			output, err = writer.CreateFormFile(part.key, part.filename)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := output.Write(part.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	token, _ := signJWT(s.jwtKey)
	r := httptest.NewRequest("POST", "/api/offensive/targets", &body)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Cookie", "private-browser-cookie")
	w := httptest.NewRecorder()
	offensiveLegacyHandler(s).ServeHTTP(w, r)
	return w
}

func TestOffensiveUploadForwardsOnlyBoundedTargetData(t *testing.T) {
	id := uuid.NewString()
	var received map[string]string
	s, _ := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/targets" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+offensiveTestToken || r.Header.Get("Cookie") != "" {
			t.Error("invalid upstream upload request")
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"id": id, "name": received["name"]})
	}))
	for _, kind := range []string{"api", "source"} {
		filename := "source.zip"
		if kind == "api" {
			filename = "spec.YAML"
		}
		parts := []offensiveUploadPart{{"file", filename, []byte("actual uploaded bytes")}, {"kind", "", []byte(kind)}, {"name", "", []byte(" 내 진단 대상 ")}}
		if kind == "api" {
			parts = append(parts, offensiveUploadPart{"base_url", "", []byte("http://crapi-web:80/api")})
		}
		w := offensiveMultipartRequest(t, s, parts)
		decoded, err := base64.StdEncoding.DecodeString(received["content_base64"])
		if w.Code != 201 || err != nil || string(decoded) != "actual uploaded bytes" || received["name"] != "내 진단 대상" || received["filename"] != filename || received["kind"] != kind || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Body.String(), received)
		}
		if kind == "source" && received["base_url"] != "" {
			t.Fatal("source upload carried URL")
		}
		received = nil
	}
}

func TestOffensiveUploadRejectsAmbiguousOrOversizeInput(t *testing.T) {
	var calls atomic.Int32
	s, _ := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{}`)
	}))
	base := []offensiveUploadPart{{"kind", "", []byte("source")}, {"name", "", []byte("source")}, {"file", "source.zip", []byte("zip bytes")}}
	for _, extra := range []offensiveUploadPart{{"kind", "", []byte("api")}, {"file", "other.zip", []byte("another zip")}, {"url", "", []byte("http://other")}, {"command", "", []byte("run")}, {"base_url", "", []byte("http://other")}} {
		parts := append(append([]offensiveUploadPart{}, base...), extra)
		w := offensiveMultipartRequest(t, s, parts)
		if w.Code != 400 {
			t.Fatal(extra.key, w.Code, w.Body.String())
		}
	}
	for _, bad := range []struct {
		kind, name, filename, baseURL string
		contentSize                   int
		want                          int
	}{
		{"source", "name", "source.tar", "", 1, 400},
		{"source", "", "source.zip", "", 1, 400},
		{"source", strings.Repeat("가", 101), "source.zip", "", 1, 400},
		{"source", "line\nbreak", "source.zip", "", 1, 400},
		{"source", "source", "source.zip", "", 0, 400},
		{"source", "source", "source.zip", "", offensiveSourceUploadLimit + 1, 413},
		{"api", "api", "schema.json", "", 1, 400},
		{"api", "api", "schema.exe", "http://crapi-web", 1, 400},
		{"api", "api", "schema.yaml", "http://crapi-web", offensiveSchemaUploadLimit + 1, 413},
	} {
		parts := []offensiveUploadPart{{"kind", "", []byte(bad.kind)}, {"name", "", []byte(bad.name)}, {"base_url", "", []byte(bad.baseURL)}, {"file", bad.filename, bytes.Repeat([]byte("x"), bad.contentSize)}}
		w := offensiveMultipartRequest(t, s, parts)
		if w.Code != bad.want {
			t.Fatal(bad.kind, bad.filename, bad.contentSize, w.Code, w.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid uploads reached runner", calls.Load())
	}
}

func TestOffensiveCustomRunSelectionAndTransientBearer(t *testing.T) {
	id := uuid.NewString()
	const privateBearer = "user-private-bearer-token"
	var calls atomic.Int32
	_, request := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["target_id"] != id || body["bearer_token"] != privateBearer {
			t.Error("missing selected target or transient token")
		}
		json.NewEncoder(w).Encode(map[string]string{"error": "credential echo " + privateBearer + " " + offensiveTestToken})
	}))
	for _, body := range []string{
		`{"kind":"source","target_id":"` + id + `","bearer_token":"` + privateBearer + `"}`,
		`{"kind":"source","target_id":"` + id + `","operation_ids":["GET /users"]}`,
		`{"kind":"api","target_id":"` + id + `","operation_ids":["GET /users","GET /users"]}`,
		`{"kind":"api","target_id":"` + id + `","operation_ids":["GET\n/users"]}`,
		`{"kind":"api","target_id":"` + id + `","bearer_token":"token\r\nHeader: value"}`,
		`{"kind":"api","target_id":"not-registered"}`,
		`{"kind":"api","target_id":"` + id + `","base_url":"http://arbitrary"}`,
	} {
		w := request("POST", "/api/offensive/runs", body)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid runs forwarded")
	}
	w := request("POST", "/api/offensive/runs", `{"kind":"api","target_id":"`+id+`","operation_ids":["GET /users"],"bearer_token":"`+privateBearer+`"}`)
	if w.Code != 200 || calls.Load() != 1 || strings.Contains(w.Body.String(), privateBearer) || strings.Contains(w.Body.String(), offensiveTestToken) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestOffensiveUploadedReviewUsesImmutableSelectedScope(t *testing.T) {
	targetID := uuid.NewString()
	run := offensiveRun{ID: uuid.NewString(), Kind: "api", TargetID: targetID, OperationIDs: []string{"GET /users"}, TargetSnapshot: offensiveTargetSnapshot{
		ID: targetID, Kind: "api", Origin: "upload", Name: "my API", URL: "http://service.test/v1", SHA256: strings.Repeat("a", 64),
		Operations: []offensiveOperation{{ID: "GET /users", Method: "GET", Path: "/users"}, {ID: "GET /admin", Method: "GET", Path: "/admin"}},
	}}
	description, goal, seed, err := offensiveReviewGoal(run)
	if err != nil || seed != "http://service.test/v1" || !strings.Contains(description, "사용자 API") || !strings.Contains(goal, `"path":"/users"`) || strings.Contains(goal, `"path":"/admin"`) || strings.Contains(goal, "crapi-web") || !strings.Contains(goal, "token used for the scanner was transient") {
		t.Fatal(description, goal, seed, err)
	}
	for _, mutate := range []func(*offensiveRun){
		func(r *offensiveRun) { r.OperationIDs = nil },
		func(r *offensiveRun) { r.OperationIDs = []string{"GET /unselected"} },
		func(r *offensiveRun) { r.OperationIDs = []string{"GET /users", "GET /users"} },
		func(r *offensiveRun) { r.TargetSnapshot.SHA256 = "not-a-hash" },
		func(r *offensiveRun) { r.TargetSnapshot.ID = uuid.NewString() },
		func(r *offensiveRun) { r.TargetSnapshot.URL = "http://user:secret@service.test" },
		func(r *offensiveRun) { r.TargetSnapshot.URL = "file:///etc/passwd" },
		func(r *offensiveRun) {
			r.TargetSnapshot.Operations = []offensiveOperation{{ID: "GET /users", Method: "POST", Path: "/users"}}
		},
		func(r *offensiveRun) {
			r.TargetSnapshot.Operations = []offensiveOperation{{ID: "GET /users", Method: "GET", Path: "/%2e%2e/admin"}}
		},
	} {
		bad := run
		mutate(&bad)
		if _, _, _, err := offensiveReviewGoal(bad); err == nil {
			t.Fatal("invalid review scope accepted", bad)
		}
	}
	run.Kind, run.TargetSnapshot.Kind = "source", "source"
	run.TargetSnapshot.SourcePath = "/app/private/config"
	run.OperationIDs = nil
	_, goal, seed, err = offensiveReviewGoal(run)
	if err != nil || !strings.Contains(goal, "/app/data/offensive/targets/"+targetID+"/source") || strings.Contains(goal, "/app/private") || strings.Contains(goal, "/benchmark/src") || !strings.Contains(goal, "Do not execute or build uploaded code") || !strings.Contains(seed, targetID) {
		t.Fatal(goal, seed, err)
	}
}

func TestOffensiveDiscoveryRegistrationForwardsOnlySelectedMode(t *testing.T) {
	const privateHARToken = "uploaded-har-test-credential"
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:18888/api/users","headers":[{"name":"Authorization","value":"Bearer ` + privateHARToken + `"}]}}]}}`)
	var received map[string]string
	s, _ := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/targets" || r.Header.Get("Authorization") != "Bearer "+offensiveTestToken || r.Header.Get("Cookie") != "" {
			t.Error("upload credentials or scope were not isolated")
		}
		received = nil
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"id": uuid.NewString(), "input_mode": received["input_mode"]})
	}))
	for _, mode := range []string{"url", "har"} {
		parts := []offensiveUploadPart{{"input_mode", "", []byte(mode)}, {"kind", "", []byte("api")}, {"name", "", []byte("내 API")}, {"base_url", "", []byte("http://crapi-web:80/api")}}
		if mode == "har" {
			parts = append(parts, offensiveUploadPart{"har_origin", "", []byte("http://localhost:18888")}, offensiveUploadPart{"file", "browser.HAR", har})
		}
		w := offensiveMultipartRequest(t, s, parts)
		if w.Code != 201 || received["input_mode"] != mode || received["kind"] != "api" || received["base_url"] != "http://crapi-web:80/api" || received["name"] != "내 API" || strings.Contains(w.Body.String(), privateHARToken) || strings.Contains(w.Body.String(), offensiveTestToken) {
			t.Fatal(mode, w.Code, w.Body.String())
		}
		if mode == "url" {
			if _, found := received["filename"]; found {
				t.Fatal("URL registration included a filename")
			}
			if _, found := received["content_base64"]; found {
				t.Fatal("URL registration included file bytes")
			}
			if len(received) != 4 {
				t.Fatal("unexpected URL registration fields")
			}
		} else {
			decoded, err := base64.StdEncoding.DecodeString(received["content_base64"])
			if err != nil || !bytes.Equal(decoded, har) || received["filename"] != "browser.HAR" || received["har_origin"] != "http://localhost:18888" || len(received) != 7 {
				t.Fatal("HAR was not passed intact to the dedicated sanitizer")
			}
		}
	}
}

func TestOffensiveDiscoveryRegistrationRejectsAmbiguousInput(t *testing.T) {
	var calls atomic.Int32
	s, _ := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{}`)
	}))
	base := []offensiveUploadPart{{"kind", "", []byte("api")}, {"name", "", []byte("API")}, {"base_url", "", []byte("http://crapi-web:80")}}
	for _, tc := range []struct {
		name  string
		parts []offensiveUploadPart
	}{
		{"missing mode still requires OpenAPI file", nil},
		{"empty mode", []offensiveUploadPart{{"input_mode", "", nil}}},
		{"unknown mode", []offensiveUploadPart{{"input_mode", "", []byte("crawl-all")}}},
		{"URL with file", []offensiveUploadPart{{"input_mode", "", []byte("url")}, {"file", "browser.har", []byte(`{}`)}}},
		{"URL with empty file", []offensiveUploadPart{{"input_mode", "", []byte("url")}, {"file", "browser.har", nil}}},
		{"duplicate mode", []offensiveUploadPart{{"input_mode", "", []byte("url")}, {"input_mode", "", []byte("har")}}},
		{"URL with HAR origin", []offensiveUploadPart{{"input_mode", "", []byte("url")}, {"har_origin", "", []byte("http://localhost:18888")}}},
		{"HAR missing file", []offensiveUploadPart{{"input_mode", "", []byte("har")}}},
		{"HAR empty file", []offensiveUploadPart{{"input_mode", "", []byte("har")}, {"file", "browser.har", nil}}},
		{"HAR file without filename", []offensiveUploadPart{{"input_mode", "", []byte("har")}, {"file", "", []byte(`{}`)}}},
		{"HAR invalid extension", []offensiveUploadPart{{"input_mode", "", []byte("har")}, {"file", "browser.yaml", []byte(`{}`)}}},
		{"HAR duplicate files", []offensiveUploadPart{{"input_mode", "", []byte("har")}, {"file", "one.har", []byte(`{}`)}, {"file", "two.har", []byte(`{}`)}}},
		{"HAR origin control character", []offensiveUploadPart{{"input_mode", "", []byte("har")}, {"har_origin", "", []byte("http://local\nhost")}, {"file", "browser.har", []byte(`{}`)}}},
		{"HAR duplicate origin", []offensiveUploadPart{{"input_mode", "", []byte("har")}, {"har_origin", "", []byte("http://localhost:1")}, {"har_origin", "", []byte("http://localhost:2")}, {"file", "browser.har", []byte(`{}`)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := offensiveMultipartRequest(t, s, append(append([]offensiveUploadPart{}, base...), tc.parts...))
			if w.Code != 400 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	for _, mode := range []string{"openapi", "har", "url"} {
		parts := []offensiveUploadPart{{"kind", "", []byte("source")}, {"name", "", []byte("source")}, {"input_mode", "", []byte(mode)}, {"file", "source.zip", []byte("zip bytes")}}
		if w := offensiveMultipartRequest(t, s, parts); w.Code != 400 {
			t.Fatal("source accepted API input mode", mode, w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid discovery registrations reached runner")
	}
}

func TestOffensiveHARUploadHasIndependentSizeLimit(t *testing.T) {
	var calls atomic.Int32
	s, _ := offensiveLegacyProxyFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		io.WriteString(w, `{}`)
	}))
	for _, tc := range []struct{ size, status int }{{offensiveSchemaUploadLimit + 1, 201}, {offensiveHARUploadLimit, 201}, {offensiveHARUploadLimit + 1, 413}} {
		parts := []offensiveUploadPart{{"file", "browser.json", bytes.Repeat([]byte("x"), tc.size)}, {"kind", "", []byte("api")}, {"input_mode", "", []byte("har")}, {"name", "", []byte("HAR")}, {"base_url", "", []byte("http://crapi-web:80")}}
		if w := offensiveMultipartRequest(t, s, parts); w.Code != tc.status {
			t.Fatal(tc.size, w.Code, w.Body.String())
		}
	}
	if calls.Load() != 2 {
		t.Fatal("oversize HAR reached runner")
	}
}

func TestOffensiveDiscoveryReviewSeparatesInventoryFromContract(t *testing.T) {
	targetID := uuid.NewString()
	run := offensiveRun{ID: uuid.NewString(), Kind: "api", TargetID: targetID, OperationIDs: []string{"GET /api/users"}, TargetSnapshot: offensiveTargetSnapshot{
		ID: targetID, Kind: "api", Origin: "upload", URL: "http://crapi-web:80", ScopeURL: "http://crapi-web:80/api", SHA256: strings.Repeat("a", 64),
		Operations: []offensiveOperation{{ID: "GET /api/users", Method: "GET", Path: "/api/users"}, {ID: "GET /admin", Method: "GET", Path: "/admin"}},
	}}
	for _, mode := range []string{"har", "url"} {
		run.TargetSnapshot.InputMode = mode
		run.TargetSnapshot.HAROrigin = "http://localhost:18888"
		_, goal, seed, err := offensiveReviewGoal(run)
		if err != nil || seed != "http://crapi-web:80" || !strings.Contains(goal, "NOT a supplied API contract") || !strings.Contains(goal, "Do not conclude contract violations") || !strings.Contains(goal, "only GET or HEAD") || !strings.Contains(goal, "Do not create accounts, discover unrelated paths") || !strings.Contains(goal, "http://crapi-web:80/api") || strings.Contains(goal, `"path":"/admin"`) || strings.Contains(goal, "http://localhost:18888") {
			t.Fatal(mode, goal, seed, err)
		}
		if mode == "har" && (!strings.Contains(goal, "original bytes had SHA-256") || !strings.Contains(goal, "historical provenance only")) {
			t.Fatal("HAR provenance confused with runtime scope")
		}
		if mode == "url" && !strings.Contains(goal, "Discovery coverage is incomplete") {
			t.Fatal("discovery coverage overstated")
		}
		for _, mutate := range []func(*offensiveRun){
			func(r *offensiveRun) { r.TargetSnapshot.ScopeURL = "" },
			func(r *offensiveRun) { r.TargetSnapshot.ScopeURL = "http://other.test/api" },
			func(r *offensiveRun) { r.TargetSnapshot.ScopeURL = "http://secret:password@crapi-web:80/api" },
			func(r *offensiveRun) { r.TargetSnapshot.ScopeURL = "http://crapi-web:80/api?token=secret" },
			func(r *offensiveRun) { r.TargetSnapshot.ScopeURL = "http://crapi-web:80/api/%2e%2e" },
			func(r *offensiveRun) { r.OperationIDs = []string{"GET /admin"} },
			func(r *offensiveRun) { r.TargetSnapshot.InputMode = "invented" },
		} {
			bad := run
			mutate(&bad)
			if _, _, _, err := offensiveReviewGoal(bad); err == nil {
				t.Fatal("discovered review accepted invalid provenance or scope", bad)
			}
		}
	}
}
