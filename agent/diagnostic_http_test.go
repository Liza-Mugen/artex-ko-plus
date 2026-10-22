package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/guard"
)

func TestDiagnosticHTTPToolDoesNotFollowRedirectOrChangeState(t *testing.T) {
	var escaped atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		escaped.Add(1)
		_, _ = w.Write([]byte("outside"))
	}))
	defer outside.Close()
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/allowed/redirect" {
			http.Redirect(w, r, outside.URL+"/", http.StatusFound)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			t.Errorf("unexpected method %s", r.Method)
		}
		_, _ = w.Write([]byte("lab evidence"))
	}))
	defer inside.Close()
	g := guard.New()
	if err := g.SetDiagnosticScope([]string{inside.URL + "/allowed"}); err != nil {
		t.Fatal(err)
	}
	tool := diagnosticHTTPTool(g)
	for _, tc := range []struct {
		input string
		want  string
	}{
		{fmt.Sprintf(`{"url":%q,"method":"GET"}`, inside.URL+"/allowed/x"), "lab evidence"},
		{fmt.Sprintf(`{"url":%q,"method":"GET"}`, inside.URL+"/allowed/redirect"), "302"},
		{fmt.Sprintf(`{"url":%q,"method":"POST"}`, inside.URL+"/allowed/x"), "only GET and HEAD"},
		{fmt.Sprintf(`{"url":%q,"method":"GET"}`, outside.URL+"/"), "outside saved diagnostic scope"},
	} {
		result, err := tool.Call(context.Background(), []byte(tc.input), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(result.Flatten(), tc.want) {
			t.Errorf("result for %s missing %q: %#v", tc.input, tc.want, result)
		}
	}
	if escaped.Load() != 0 {
		t.Fatal("HTTP redirect reached the outside target")
	}
}
