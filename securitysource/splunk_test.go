package securitysource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sourceFixture(t *testing.T, h http.HandlerFunc) (Config, Credentials) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	fp := sha256.Sum256(s.Certificate().Raw)
	return Config{BaseURL: s.URL, Index: "security", AuditSourcetype: "app:audit", AlertSourcetype: "waf:alert", CorrelationField: "artex_verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(fp[:])}, Credentials{Username: "reader", Password: "test-only"}
}

const testCorrelation = "bbbbbbbb-aaaa-cccc-dddd-eeeeeeeeeeee"

func sourceQuery() Query {
	end := time.Now().UTC().Add(-time.Second)
	return Query{CorrelationID: testCorrelation, Start: end.Add(-time.Minute), End: end}
}
func resultLine(t time.Time, correlation, action string) string {
	raw, _ := json.Marshal(map[string]any{"_time": t.Format("2006-01-02T15:04:05.000000-0700"), "_cd": "1:2", "_raw": fmt.Sprintf(`{"artex_verification_id":%q,"action":%q}`, correlation, action)})
	return `{"preview":false,"lastrow":true,"result":` + string(raw) + "}\n"
}

func TestPurpleSourceFetchPinnedTLSAndRealQuery(t *testing.T) {
	q := sourceQuery()
	calls := 0
	c, a := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/search/v2/jobs/export" || r.Method != "POST" {
			t.Errorf("unexpected operation %s %s", r.Method, r.URL.Path)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "reader" || p != "test-only" {
			t.Error("credentials not scoped to configured endpoint")
		}
		_ = r.ParseForm()
		search := r.Form.Get("search")
		if r.Form.Get("output_time_format") != "%Y-%m-%dT%H:%M:%S.%6N%z" {
			t.Error("export can return an ambiguous timezone abbreviation")
		}
		if !strings.Contains(search, `where 'artex_verification_id' = "`+testCorrelation+`"`) || r.Form.Get("earliest_time") == "" || r.Form.Get("latest_time") == "" || strings.Contains(search, "collect ") {
			t.Errorf("unbounded or wrong query %s", search)
		}
		for _, field := range []string{"artex_verification_id", "action"} {
			if !strings.Contains(search, fmt.Sprintf(`"%s"=mvdedup('%s')`, field, field)) {
				t.Errorf("automatic and explicit JSON extraction can duplicate %s: %s", field, search)
			}
		}
		if strings.Contains(search, " | fields ") || strings.Contains(search, "mvindex(") {
			t.Error("search discarded native fields or selected one ambiguous value")
		}
		calls++
		_, _ = w.Write([]byte(resultLine(q.Start.Add(time.Second), testCorrelation, "blocked")))
	})
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:1")
	out, e := Fetch(t.Context(), c, a, q)
	if e != nil {
		t.Fatal(e)
	}
	if calls != 2 || !out.Complete || len(out.Events) != 2 || out.Events[0].Kind != "audit" || out.Events[1].Kind != "alert" || out.Events[0].Action != "blocked" || len(out.Events[0].Raw) == 0 || out.CollectedAt.IsZero() {
		t.Fatalf("evidence: %+v", out)
	}
	if out.Events[0].CorrelationID != testCorrelation || out.WindowStart != q.Start || out.WindowEnd != q.End {
		t.Fatal("correlation window changed")
	}
}

func TestPurpleSourceSplunkExportTimePreservesOffsetAndScope(t *testing.T) {
	want := time.Date(2026, 10, 10, 3, 0, 0, 123456000, time.UTC)
	for _, input := range []string{"2026-10-10T12:00:00.123456+0900", "2026-10-09T20:00:00.123456-0700", "2026-10-10T03:00:00.123456+0000"} {
		got, err := eventTime(input)
		if err != nil || !got.Equal(want) || got.Location() != time.UTC {
			t.Fatalf("export time offset or precision lost: got=%v error=%v", got, err)
		}
	}
	for _, input := range []any{"2026-10-10 12:00:00.123 KST", "2026-10-10T12:00:00.123456", []string{"2026-10-10T12:00:00.123456+0900", "2026-10-10T12:01:00.123456+0900"}} {
		if _, err := eventTime(input); err == nil {
			t.Fatal("ambiguous or multivalued export time accepted")
		}
	}
	c := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	q := Query{CorrelationID: testCorrelation, Start: want.Add(-time.Second), End: want.Add(time.Second)}
	for _, at := range []time.Time{q.Start.Add(-time.Microsecond), q.End} {
		out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
		if err := parseExport([]byte(resultLine(at.In(time.FixedZone("KST", 9*3600)), testCorrelation, "blocked")), "audit", c, q, out); err != nil {
			t.Fatal(err)
		}
		if out.Complete || len(out.Events) != 0 {
			t.Fatal("numeric offset moved an event into the execution window")
		}
	}
}

func TestPurpleSourceConflictingMultivalueFieldsStayInconclusive(t *testing.T) {
	q := sourceQuery()
	for _, tc := range []struct {
		name         string
		correlation  any
		action       any
		wantEvents   int
		wantComplete bool
	}{
		{"conflicting correlation", []string{testCorrelation, "other-execution"}, "blocked", 0, false},
		{"conflicting policy action", testCorrelation, []string{"blocked", "allowed"}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				row, err := json.Marshal(map[string]any{
					"_time": q.Start.Add(time.Second).Format(time.RFC3339Nano), "_cd": "1:2",
					"artex_verification_id": tc.correlation, "action": tc.action,
					"_raw": fmt.Sprintf(`{"artex_verification_id":%q,"action":"blocked"}`, testCorrelation),
				})
				if err != nil {
					t.Fatal(err)
				}
				fmt.Fprintf(w, "{\"lastrow\":true,\"result\":%s}\n", row)
			})
			out, err := Fetch(t.Context(), c, auth, q)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Events) != tc.wantEvents || out.Complete != tc.wantComplete {
				t.Fatalf("conflicting field changed scope or completeness: events=%d complete=%v", len(out.Events), out.Complete)
			}
			for _, event := range out.Events {
				if event.Action != "unknown" {
					t.Fatal("selected a policy action from conflicting values")
				}
			}
		})
	}
}
func TestPurpleSourceRejectsInvalidSettingsAndQueries(t *testing.T) {
	c, a := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid request reached network") })
	for _, mutate := range []func(*Config){func(x *Config) { x.BaseURL = "http://example.test" }, func(x *Config) { x.BaseURL = "https://user:pass@example.test" }, func(x *Config) { x.Index = `main | delete` }, func(x *Config) { x.CorrelationField = `x' | delete` }, func(x *Config) { x.AlertSourcetype = x.AuditSourcetype }, func(x *Config) { x.TLSFingerprint = "bad" }} {
		bad := c
		mutate(&bad)
		if _, e := Fetch(t.Context(), bad, a, sourceQuery()); e == nil {
			t.Fatal("invalid config accepted")
		}
	}
	q := sourceQuery()
	q.CorrelationID = `x" | delete`
	if _, e := Fetch(t.Context(), c, a, q); e == nil {
		t.Fatal("query injection accepted")
	}
	q = sourceQuery()
	q.Start = q.End.Add(-25 * time.Hour)
	if _, e := Fetch(t.Context(), c, a, q); e == nil {
		t.Fatal("unbounded window accepted")
	}
	if _, e := Fetch(t.Context(), c, Credentials{Token: "a", Username: "b", Password: "c"}, sourceQuery()); e == nil {
		t.Fatal("ambiguous auth accepted")
	}
}
func TestPurpleSourceRefusesWrongCertificateAndRedirects(t *testing.T) {
	c, a := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/credentials", 302)
	})
	if _, e := Fetch(t.Context(), c, a, sourceQuery()); e == nil {
		t.Fatal("redirect accepted")
	}
	c.TLSFingerprint = strings.Repeat("0", 64)
	if _, e := Fetch(t.Context(), c, a, sourceQuery()); e == nil {
		t.Fatal("wrong certificate accepted")
	}
}
func TestPurpleSourceIncompleteAndUncorrelatedEvidence(t *testing.T) {
	q := sourceQuery()
	c := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	for _, body := range []string{resultLine(q.Start.Add(time.Second), "other-execution", "blocked"), resultLine(q.Start.Add(-time.Second), testCorrelation, "blocked"), `{"preview":true,"result":{}}` + "\n", `{"messages":[{"type":"WARN","text":"private internal details"}]}` + "\n"} {
		out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
		if e := parseExport([]byte(body), "audit", c, q, out); e != nil {
			t.Fatal(e)
		}
		if out.Complete || len(out.Events) != 0 {
			t.Fatal("incomplete or foreign event accepted")
		}
		for _, warning := range out.Warnings {
			if strings.Contains(warning, "private internal") {
				t.Fatal("remote error leaked")
			}
		}
	}
	for _, body := range []string{"{not json", `{"messages":[{"type":"FATAL","text":"secret"}]}`} {
		if e := parseExport([]byte(body), "audit", c, q, &Evidence{}); e == nil {
			t.Fatal("invalid response accepted")
		}
	}
}
func TestPurpleSourceUnknownActionDoesNotInferFromHTTPStatus(t *testing.T) {
	q := sourceQuery()
	c := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	if e := parseExport([]byte(resultLine(q.Start.Add(time.Second), testCorrelation, "403")), "audit", c, q, out); e != nil {
		t.Fatal(e)
	}
	if len(out.Events) != 1 || out.Events[0].Action != "unknown" {
		t.Fatal("HTTP status was treated as policy action")
	}
	q.CorrelationID = "no-such-event-correlated"
	if e := parseExport(nil, "alert", c, q, out); e != nil {
		t.Fatal(e)
	}
}

func TestPurpleSourceCompletedZeroAlertExportIsComplete(t *testing.T) {
	q := sourceQuery()
	calls := 0
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(r.Form.Get("search"), `sourcetype="app:audit"`) {
			fmt.Fprint(w, resultLine(q.Start.Add(time.Second), testCorrelation, "allowed"))
		} else {
			fmt.Fprintln(w, `{"preview":false,"lastrow":true}`)
		}
	})
	out, err := Fetch(t.Context(), c, auth, q)
	if err != nil || calls != 2 || !out.Complete || len(out.Warnings) != 0 || len(out.Events) != 1 || out.Events[0].Kind != "audit" {
		t.Fatal("completed zero-alert response lost its search completeness")
	}
	for _, body := range []string{`{"preview":false,"lastrow":false}`, `{"preview":true,"lastrow":true}`, `{"unexpected":true}`} {
		out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
		if err := parseExport([]byte(body), "alert", c, q, out); err != nil {
			t.Fatal(err)
		}
		if out.Complete {
			t.Fatal("unfinished or unknown response counted as a completed zero-alert search")
		}
	}
}
func TestPurpleSourceLimitsAndRedactedFailures(t *testing.T) {
	c, a := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("secret private detail"))
	})
	_, e := Fetch(t.Context(), c, a, sourceQuery())
	if e == nil || strings.Contains(e.Error(), "secret") || strings.Contains(e.Error(), c.BaseURL) {
		t.Fatalf("remote error disclosure: %v", e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := Fetch(ctx, c, a, sourceQuery()); e == nil {
		t.Fatal("cancelled fetch succeeded")
	}
	q := sourceQuery()
	cfg := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	if e := parseExport([]byte(strings.Repeat(resultLine(q.Start.Add(time.Second), testCorrelation, "allowed"), 201)), "audit", cfg, q, out); e != nil {
		t.Fatal(e)
	}
	if out.Complete {
		t.Fatal("truncated search counted complete")
	}
}

func TestPurpleSourceConflictingIdentityAndExactNumbers(t *testing.T) {
	q := sourceQuery()
	c := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	stream := resultLine(q.Start.Add(time.Second), testCorrelation, "blocked") + resultLine(q.Start.Add(time.Second), testCorrelation, "allowed")
	if e := parseExport([]byte(stream), "audit", c, q, out); e != nil {
		t.Fatal(e)
	}
	if out.Complete || len(out.Warnings) == 0 {
		t.Fatal("conflicting duplicate was accepted as blocked-only")
	}
	line := strings.Replace(resultLine(q.Start.Add(time.Second), testCorrelation, "blocked"), `"_cd":"1:2"`, `"_cd":"1:2","large":9007199254740993`, 1)
	out = &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	if e := parseExport([]byte(line), "audit", c, q, out); e != nil {
		t.Fatal(e)
	}
	if len(out.Events) != 1 || !strings.Contains(string(out.Events[0].Raw), "9007199254740993") {
		t.Fatal("original numeric evidence was rounded")
	}
}

func TestPurpleSourceMultiIndexStreamsAndLegacyNormalization(t *testing.T) {
	q := sourceQuery()
	searches := []string{}
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		search := r.Form.Get("search")
		searches = append(searches, search)
		index, st := "", ""
		switch {
		case strings.Contains(search, `index="ag_juice_shop" sourcetype="juice:audit"`):
			index, st = "ag_juice_shop", "juice:audit"
		case strings.Contains(search, `index="ag_vuln_bank" sourcetype="bank:alert"`):
			index, st = "ag_vuln_bank", "bank:alert"
		default:
			t.Errorf("unexpected stream query: %s", search)
		}
		row, _ := json.Marshal(map[string]any{"_time": q.Start.Add(time.Second).Format(time.RFC3339Nano), "_cd": "1:2", "index": index, "sourcetype": st, "artex_verification_id": testCorrelation, "action": "blocked"})
		fmt.Fprintf(w, "{\"preview\":false,\"lastrow\":true,\"result\":%s}\n", row)
	})
	c.Index, c.AuditSourcetype, c.AlertSourcetype = "", "", ""
	c.Streams = []LogStream{{Index: "ag_juice_shop", Sourcetype: "juice:audit", Kind: "audit"}, {Index: "ag_vuln_bank", Sourcetype: "bank:alert", Kind: "alert"}}
	validated, err := Validate(c)
	if err != nil || len(validated.Streams) != 2 {
		t.Fatalf("streams-only config rejected: %+v, %v", validated, err)
	}
	out, err := Fetch(t.Context(), c, auth, q)
	if err != nil || len(searches) != 2 || !out.Complete || len(out.Events) != 2 {
		t.Fatalf("multi-index fetch failed: evidence=%+v err=%v searches=%v", out, err, searches)
	}
	if out.Events[0].Index != "ag_juice_shop" || out.Events[0].Sourcetype != "juice:audit" || out.Events[1].Index != "ag_vuln_bank" || out.Events[1].Sourcetype != "bank:alert" {
		t.Fatalf("event provenance lost: %+v", out.Events)
	}
	legacy := c
	legacy.Streams, legacy.Index, legacy.AuditSourcetype, legacy.AlertSourcetype = nil, "old", "old:audit", "old:alert"
	normalized, err := Validate(legacy)
	if err != nil || len(normalized.Streams) != 2 || !EqualConfig(legacy, normalized) {
		t.Fatalf("legacy normalization changed meaning: %+v, %v", normalized, err)
	}
	streamsOnly := normalized
	streamsOnly.Index, streamsOnly.AuditSourcetype, streamsOnly.AlertSourcetype = "", "", ""
	if !EqualConfig(legacy, streamsOnly) {
		t.Fatal("moving unchanged legacy fields to streams changed connection semantics")
	}
	changed := normalized
	changed.Streams = append([]LogStream(nil), normalized.Streams...)
	changed.Streams[0].Index = "different"
	if EqualConfig(normalized, changed) {
		t.Fatal("effective stream index change was ignored")
	}
}

func TestPurpleSourceStreamValidationAndAggregateBound(t *testing.T) {
	c, _ := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Fatal("invalid config reached network") })
	c.Index, c.AuditSourcetype, c.AlertSourcetype = "", "", ""
	c.Streams = []LogStream{{Index: "one", Sourcetype: "web", Kind: "audit"}, {Index: "two", Sourcetype: "waf", Kind: "alert"}}
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.Streams[0].Index = "*" },
		func(cfg *Config) { cfg.Streams[0].Sourcetype = "web?" },
		func(cfg *Config) { cfg.Streams[0].Kind = "other" },
		func(cfg *Config) { cfg.Streams[1].Index, cfg.Streams[1].Sourcetype = "one", "web" },
		func(cfg *Config) { cfg.Streams = cfg.Streams[:1] },
	} {
		bad := c
		bad.Streams = append([]LogStream(nil), c.Streams...)
		mutate(&bad)
		if _, err := Validate(bad); err == nil {
			t.Fatalf("invalid stream config accepted: %+v", bad.Streams)
		}
	}
	q := sourceQuery()
	out := &Evidence{Events: make([]Event, maxRows), Complete: true}
	if err := parseStreamExport([]byte(resultLine(q.Start.Add(time.Second), testCorrelation, "blocked")), c.Streams[0], c, q, out, map[string][32]byte{}); err != nil || out.Complete || len(out.Events) != maxRows {
		t.Fatalf("aggregate 200-row cap failed: %+v, %v", out, err)
	}
}

func TestPurpleSourceListIndexesAndPerStreamProbe(t *testing.T) {
	probes := 0
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/services/data/indexes":
			if r.Method != http.MethodGet || r.URL.Query().Get("count") != "128" {
				t.Errorf("unbounded discovery: %s", r.URL)
			}
			fmt.Fprint(w, `{"entry":[{"name":"z_index"},{"name":"*"},{"name":"a_index"},{"name":"z_index"}]}`)
		case "/services/search/v2/jobs/export":
			probes++
			if r.Method != http.MethodPost || r.ParseForm() != nil || !strings.Contains(r.Form.Get("search"), `index="security" sourcetype="app:audit" | head 1`) || r.Form.Get("earliest_time") == "" || r.Form.Get("latest_time") == "" {
				t.Errorf("invalid stream probe: %s", r.Form.Encode())
			}
			fmt.Fprintln(w, `{"preview":false,"lastrow":true}`)
		default:
			t.Errorf("unexpected request: %s", r.URL)
		}
	})
	indexes, err := ListIndexes(t.Context(), c, auth)
	if err != nil || len(indexes) != 2 || indexes[0] != "a_index" || indexes[1] != "z_index" {
		t.Fatalf("discovery changed: %v %v", indexes, err)
	}
	probe, err := TestStream(t.Context(), c, auth, 0)
	if err != nil || !probe.Searchable || probe.HasRecentEvents || probes != 1 {
		t.Fatalf("completed empty search was not distinguished: %+v %v", probe, err)
	}
	if _, err := TestStream(t.Context(), c, auth, -1); err == nil {
		t.Fatal("invalid stream index reached search")
	}
}
