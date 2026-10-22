package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

const (
	diagnosticRequestLimit    = 20
	diagnosticConcurrentLimit = 2
)

type diagnosticGuardKey struct{}

// WithDiagnosticGuard gives the Worker only the task's own request budget and
// scope. The tool never accepts a policy or network destination from model text.
func WithDiagnosticGuard(ctx context.Context, g *Guard) context.Context {
	return context.WithValue(ctx, diagnosticGuardKey{}, g)
}

func DiagnosticGuardFromContext(ctx context.Context) *Guard {
	g, _ := ctx.Value(diagnosticGuardKey{}).(*Guard)
	if g == nil || !g.DiagnosticEnabled() {
		return nil
	}
	return g
}

// diagnosticScope is a task-owned execution boundary. It is deliberately
// independent of editable prompt constraints and intercept fallback decisions.
type diagnosticScope struct {
	URLs          []*url.URL
	Requests      int
	InFlight      int
	RunID         string
	ArtifactReads int
}

// SetDiagnosticScope enables the fail-closed diagnostic policy. An invalid or
// missing scope leaves the policy enabled with no permitted network destination.
func (g *Guard) SetDiagnosticScope(scopes []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.diagnostic == nil {
		g.diagnostic = &diagnosticScope{}
	}
	if len(scopes) == 0 || len(scopes) > 8 {
		return errors.New("diagnostic scope must contain 1–8 URLs")
	}
	parsed := make([]*url.URL, 0, len(scopes))
	for _, raw := range scopes {
		u, err := parseDiagnosticURL(raw, false)
		if err != nil {
			return err
		}
		parsed = append(parsed, u)
	}
	if len(g.diagnostic.URLs) > 0 {
		if len(g.diagnostic.URLs) != len(parsed) {
			return errors.New("diagnostic scope is already fixed")
		}
		for i := range parsed {
			if g.diagnostic.URLs[i].String() != parsed[i].String() {
				return errors.New("diagnostic scope is already fixed")
			}
		}
		return nil // idempotent; request count is never reset
	}
	g.diagnostic.URLs = parsed
	return nil
}

// DiagnosticEnabled reports whether this Guard belongs to a diagnostic task.
func (g *Guard) DiagnosticEnabled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.diagnostic != nil
}

func (g *Guard) DiagnosticScopeReady() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.diagnostic != nil && len(g.diagnostic.URLs) > 0
}

// SetDiagnosticRunID pins the runner history whose named artifacts a Worker may
// read. The task marker, not model-provided input, selects this UUID.
func (g *Guard) SetDiagnosticRunID(id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id {
		return errors.New("invalid diagnostic run ID")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.diagnostic == nil {
		g.diagnostic = &diagnosticScope{}
	}
	if g.diagnostic.RunID != "" && g.diagnostic.RunID != id {
		return errors.New("diagnostic run ID is already fixed")
	}
	g.diagnostic.RunID = id
	return nil
}

// UseDiagnosticArtifact reserves one manifest-verified artifact read.
func (g *Guard) UseDiagnosticArtifact(name string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.diagnostic == nil || g.diagnostic.RunID == "" || len(g.diagnostic.URLs) == 0 {
		g.recordLocked("diagnostic_read_artifact", "block", "artifact source is not configured", "")
		return "", errors.New("diagnostic artifact source is not configured")
	}
	if g.diagnostic.ArtifactReads >= 20 {
		g.recordLocked("diagnostic_read_artifact", "block", "artifact read limit reached", "")
		return "", errors.New("diagnostic artifact read limit reached")
	}
	g.diagnostic.ArtifactReads++
	g.recordLocked("diagnostic_read_artifact", "allow", "", name)
	return g.diagnostic.RunID, nil
}

// UseDiagnosticRequest validates and reserves one bounded GET/HEAD request. The
// same task Guard is shared by all Workers, so parallel calls share the budget.
// Validation is repeated in the HTTP tool immediately before issuing a request.
func (g *Guard) UseDiagnosticRequest(method, rawURL string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.diagnostic == nil {
		return errors.New("diagnostic policy is not enabled")
	}
	if method != "GET" && method != "HEAD" {
		g.recordLocked("scoped_http_get", "block", "only GET and HEAD are permitted", "")
		return errors.New("only GET and HEAD are permitted")
	}
	u, err := parseDiagnosticURL(rawURL, true)
	if err != nil {
		g.recordLocked("scoped_http_get", "block", "invalid URL", "")
		return err
	}
	allowed := false
	for _, base := range g.diagnostic.URLs {
		if diagnosticURLWithin(base, u) {
			allowed = true
			break
		}
	}
	if !allowed {
		g.recordLocked("scoped_http_get", "block", "URL outside saved diagnostic scope", "")
		return errors.New("URL outside saved diagnostic scope")
	}
	if g.diagnostic.Requests >= diagnosticRequestLimit {
		g.recordLocked("scoped_http_get", "block", "diagnostic request limit reached", "")
		return errors.New("diagnostic request limit reached")
	}
	if g.diagnostic.InFlight >= diagnosticConcurrentLimit {
		g.recordLocked("scoped_http_get", "block", "diagnostic concurrent request limit reached", "")
		return errors.New("diagnostic concurrent request limit reached")
	}
	g.diagnostic.Requests++
	g.diagnostic.InFlight++
	g.recordLocked("scoped_http_get", "allow", "", method+" "+u.Scheme+"://"+u.Host+u.Path)
	return nil
}

// FinishDiagnosticRequest releases the concurrency slot. The total request
// budget remains consumed even if the upstream request fails or is cancelled.
func (g *Guard) FinishDiagnosticRequest() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.diagnostic != nil && g.diagnostic.InFlight > 0 {
		g.diagnostic.InFlight--
	}
}

// DiagnosticScopesFromConstraints restores the code-created scope on a process
// restart. Human-authored constraints cannot expand this boundary.
func DiagnosticScopesFromConstraints(rows []db.Constraint) ([]string, error) {
	const prefix = "허용된 URL 접두 범위는 "
	var found bool
	var scopes []string
	for _, row := range rows {
		if row.Origin != "diagnostic-bootstrap" || row.Kind != "allow" || !strings.HasPrefix(row.Text, prefix) {
			continue
		}
		if found {
			return nil, errors.New("duplicate diagnostic scope")
		}
		found = true
		rest := strings.TrimPrefix(row.Text, prefix)
		end := strings.Index(rest, "뿐입니다.")
		if end < 0 || !strings.HasSuffix(rest[end:], "다른 호스트·포트·경로로 확장하지 마세요.") {
			return nil, errors.New("malformed diagnostic scope constraint")
		}
		if err := json.Unmarshal([]byte(rest[:end]), &scopes); err != nil {
			return nil, fmt.Errorf("decode diagnostic scope: %w", err)
		}
	}
	if !found {
		return nil, errors.New("diagnostic scope constraint missing")
	}
	return scopes, nil
}

func parseDiagnosticURL(raw string, allowQuery bool) (*url.URL, error) {
	if raw == "" || len(raw) > 4096 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t") {
		return nil, errors.New("invalid diagnostic URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" ||
		(u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" ||
		(!allowQuery && u.RawQuery != "") || u.ForceQuery ||
		strings.ContainsAny(u.Path, "\\\r\n\t") || strings.Contains(u.Path, "//") {
		return nil, errors.New("invalid diagnostic URL")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, errors.New("diagnostic URL contains path traversal")
		}
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") {
		return nil, errors.New("diagnostic URL has ambiguous encoded path")
	}
	return u, nil
}

func diagnosticURLWithin(base, u *url.URL) bool {
	if base.Scheme != u.Scheme || !strings.EqualFold(base.Hostname(), u.Hostname()) ||
		diagnosticPort(base) != diagnosticPort(u) {
		return false
	}
	prefix := strings.TrimRight(base.Path, "/")
	return prefix == "" || u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/")
}

func diagnosticPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
