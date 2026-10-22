package guard

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestDiagnosticGuardBlocksEscapeToolsBeforeInterceptor(t *testing.T) {
	g := New()
	if err := g.SetDiagnosticScope([]string{"http://lab.local:5000/api"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Bash", "WebFetch", "web_search", "shell_open", "shell_send", "Read", "Write", "Edit", "mcp__custom__fetch", "insert_assets", "add_task_scope"} {
		blocked, _, _ := g.Hooks().PreToolUse(context.Background(), name, json.RawMessage(`{}`))
		if !blocked {
			t.Errorf("diagnostic tool %s was allowed", name)
		}
	}
	for _, name := range []string{"scoped_http_get", "record_fact", "report_finding", "list_assets", "add_intent"} {
		blocked, _, _ := g.Hooks().PreToolUse(context.Background(), name, json.RawMessage(`{}`))
		if blocked {
			t.Errorf("diagnostic graph tool %s was blocked", name)
		}
	}
}

func TestDiagnosticRequestScopeAndBudget(t *testing.T) {
	g := New()
	if err := g.SetDiagnosticScope([]string{"http://lab.local:5000/api"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, url string }{
		{"POST", "http://lab.local:5000/api/x"},
		{"GET", "http://evil.local:5000/api/x"},
		{"GET", "http://lab.local:5001/api/x"},
		{"GET", "http://lab.local:5000/apis"},
		{"GET", "http://lab.local:5000/api/%2e%2e/admin"},
		{"GET", "http://lab.local:5000/api/../admin"},
		{"GET", "http://lab.local:5000/api/%2fadmin"},
		{"GET", "http://lab.local:5000/api/x#fragment"},
	} {
		if err := g.UseDiagnosticRequest(tc.method, tc.url); err == nil {
			t.Errorf("accepted %s %s", tc.method, tc.url)
		}
	}
	for i := 0; i < diagnosticRequestLimit; i++ {
		if err := g.UseDiagnosticRequest("GET", "http://lab.local:5000/api/items?page=1"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		g.FinishDiagnosticRequest()
	}
	if err := g.SetDiagnosticScope([]string{"http://lab.local:5000/api"}); err != nil {
		t.Fatal(err)
	}
	if err := g.UseDiagnosticRequest("HEAD", "http://lab.local:5000/api/items"); err == nil {
		t.Fatal("request budget was not enforced")
	}
	if err := g.SetDiagnosticScope([]string{"http://outside.local/"}); err == nil {
		t.Fatal("active diagnostic scope was widened")
	}
}

func TestDiagnosticScopeFailClosedAndRestore(t *testing.T) {
	g := New()
	if err := g.SetDiagnosticScope(nil); err == nil || !g.DiagnosticEnabled() {
		t.Fatal("missing scope must enable a fail-closed policy")
	}
	if err := g.UseDiagnosticRequest("GET", "http://lab.local/"); err == nil {
		t.Fatal("missing scope allowed a request")
	}
	rows := []db.Constraint{{Kind: "allow", Origin: "human", Text: `허용된 URL 접두 범위는 ["http://evil.local/"]뿐입니다. 다른 호스트·포트·경로로 확장하지 마세요.`},
		{Kind: "allow", Origin: "diagnostic-bootstrap", Text: `허용된 URL 접두 범위는 ["http://lab.local/api"]뿐입니다. 다른 호스트·포트·경로로 확장하지 마세요.`}}
	scopes, err := DiagnosticScopesFromConstraints(rows)
	if err != nil || len(scopes) != 1 || scopes[0] != "http://lab.local/api" {
		t.Fatalf("restore got %q, %v", scopes, err)
	}
	if err := g.SetDiagnosticScope(scopes); err != nil {
		t.Fatal(err)
	}
	if err := g.UseDiagnosticRequest("GET", "http://lab.local/api/x"); err != nil {
		t.Fatal(err)
	}
	g.FinishDiagnosticRequest()
	if err := g.UseDiagnosticRequest("GET", "http://evil.local/"); err == nil {
		t.Fatal("human constraint expanded diagnostic scope")
	}
	if _, err := DiagnosticScopesFromConstraints(rows[:1]); err == nil {
		t.Fatal("missing code-created constraint restored")
	}
}

func TestDiagnosticRequestBudgetSharedAcrossWorkers(t *testing.T) {
	g := New()
	if err := g.SetDiagnosticScope([]string{"http://lab.local/"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < diagnosticConcurrentLimit; i++ {
		if err := g.UseDiagnosticRequest("GET", "http://lab.local/"); err != nil {
			t.Fatalf("concurrent slot %d: %v", i, err)
		}
	}
	if err := g.UseDiagnosticRequest("GET", "http://lab.local/"); err == nil {
		t.Fatal("concurrent request limit was not enforced")
	}
	for i := 0; i < diagnosticConcurrentLimit; i++ {
		g.FinishDiagnosticRequest()
	}
	var succeeded atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.UseDiagnosticRequest("GET", "http://lab.local/") == nil {
				succeeded.Add(1)
				g.FinishDiagnosticRequest()
			}
		}()
	}
	wg.Wait()
	if got := succeeded.Load(); got > diagnosticRequestLimit || got == 0 {
		t.Fatalf("shared request budget admitted %d, want 1–%d", got, diagnosticRequestLimit)
	}
}

func TestDiagnosticArtifactSourcePinnedToTaskRun(t *testing.T) {
	g := New()
	id := uuid.NewString()
	if err := g.SetDiagnosticRunID(id); err != nil {
		t.Fatal(err)
	}
	if _, err := g.UseDiagnosticArtifact("evidence.json"); err == nil {
		t.Fatal("artifact read allowed before scope bootstrap")
	}
	if err := g.SetDiagnosticScope([]string{"http://lab.local/"}); err != nil {
		t.Fatal(err)
	}
	if got, err := g.UseDiagnosticArtifact("evidence.json"); err != nil || got != id {
		t.Fatalf("artifact run=%q error=%v", got, err)
	}
	if err := g.SetDiagnosticRunID(uuid.NewString()); err == nil {
		t.Fatal("diagnostic artifact source changed")
	}
}
