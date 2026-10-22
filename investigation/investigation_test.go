package investigation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testScope() Scope {
	return Scope{Target: "juice-shop:3000", PathPrefix: "/ftp", Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)}
}
func row(id, path string, extras map[string]any) string {
	m := map[string]any{"timestamp": "2026-01-01T00:05:00Z", "target": "http://juice-shop:3000", "path": path, "id": id, "source_ip": "192.0.2.1"}
	for k, v := range extras {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}
func parse(t *testing.T, content string) Collection {
	t.Helper()
	c, e := ParseFiles([]InputFile{{Name: "access.jsonl", Content: content}}, testScope(), DefaultMapping(), true, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func plan() Plan {
	return BuildPlan(FindingContext{Name: "무인증 /ftp 디렉터리 리스팅 정보 노출"})
}
func TestPlanConditionalFamilies(t *testing.T) {
	for _, tt := range []struct{ name, want string }{{"information source disclosure", "information_exposure"}, {"resource exposure", "information_exposure"}, {"RCE", "code_execution"}, {"SSRF", "ssrf"}, {"인증 우회", "authentication"}, {"unknown", "generic"}} {
		p := BuildPlan(FindingContext{Name: tt.name})
		if p.Family != tt.want {
			t.Errorf("%s family=%s", tt.name, p.Family)
		}
		if p.EngineVersion == "" || len(p.Hypotheses) < 2 || p.Method == "" {
			t.Fatal("plan lacks provenance")
		}
		for _, h := range p.Hypotheses {
			if len(h.Preconditions) == 0 || len(h.References) == 0 || len(h.BenignAlternatives) == 0 {
				t.Fatal("unconditional hypothesis", h)
			}
		}
	}
}
func TestPlanSeparatesErrorAndFileInformationExposure(t *testing.T) {
	errorPlan := BuildPlan(FindingContext{
		Name:      "`/api/ai/chat/anonymous` 비정상 JSON 처리 시 기본 500 에러 페이지를 통한 정보 노출",
		VulnClass: "CWE-209: Information Exposure Through an Error Message",
	})
	if errorPlan.Family != "error_information_exposure" || len(errorPlan.Hypotheses) != 4 {
		t.Fatalf("error disclosure plan mismatch: %+v", errorPlan)
	}
	for _, h := range errorPlan.Hypotheses {
		if h.ID == "multi_path" || h.ID == "exposed_credentials" {
			t.Fatalf("file-specific hypothesis leaked into error guidance: %s", h.ID)
		}
	}
	if !strings.Contains(strings.Join(errorPlan.Hypotheses[1].RequiredFields, " "), "Content-Type") || !strings.Contains(strings.Join(errorPlan.Hypotheses[2].RequiredFields, " "), "Server 헤더") {
		t.Fatal("error guidance lacks request and response evidence fields")
	}
	nonJSONError := BuildPlan(FindingContext{Name: "예외 화면에서 내부 스택 정보 노출", VulnClass: "CWE-209"})
	if strings.Contains(strings.Join(nonJSONError.Hypotheses[1].RequiredFields, " "), "Content-Type") || strings.Contains(nonJSONError.Hypotheses[1].Hunt, "JSON") {
		t.Fatal("non-JSON error guidance inherited JSON-specific evidence requirements")
	}
	filePlan := BuildPlan(FindingContext{Name: "무인증 /ftp 디렉터리 리스팅 정보 노출"})
	if filePlan.Family != "file_information_exposure" || filePlan.Hypotheses[1].ID != "multi_path" {
		t.Fatal("file disclosure lost its specific workflow")
	}
	genericPlan := BuildPlan(FindingContext{Name: "resource exposure"})
	if genericPlan.Family != "information_exposure" || genericPlan.Hypotheses[1].ID != "impact_review" {
		t.Fatal("generic exposure was overclassified")
	}
	authPlan := BuildPlan(FindingContext{Name: "인증 실패 오류와 계정 정보 노출"})
	if authPlan.Family != "authentication" {
		t.Fatal("authentication error was misclassified as error disclosure")
	}
}

func TestPlanDefenseFactsStaySeparateFromScenarioAndHistoricalIntrusion(t *testing.T) {
	finding := FindingContext{Name: "비정상 JSON 기본 500 에러 페이지 정보 노출", VulnClass: "CWE-209"}
	plan := BuildPlanWithDefense(finding, DefenseGuidanceContext{
		SuggestedPath:  "/api/ai/chat/anonymous",
		RetestID:       5,
		RetestStatus:   "completed",
		RetestVerdict:  "reproduced",
		RetestSummary:  "malformed JSON 요청에서 500 Server: Apache, root@localhost 노출",
		ScenarioState:  "stale",
		ExecutionID:    "5",
		ExecutionState: "stale",
	})
	if len(plan.VerifiedFacts) != 1 || !strings.Contains(plan.VerifiedFacts[0].Source, "#5") || !strings.Contains(plan.VerifiedFacts[0].Text, "HTTP 500") {
		t.Fatalf("retest fact missing provenance: %+v", plan.VerifiedFacts)
	}
	if len(plan.ScenarioAssumptions) != 0 || len(plan.ContextWarnings) != 2 {
		t.Fatalf("stale defense context was treated as current: %+v", plan)
	}
	if !strings.Contains(plan.Hypotheses[0].Statement, "/api/ai/chat/anonymous") || !strings.Contains(plan.Summary, "과거 침해") {
		t.Fatal("bounded route or investigation distinction missing")
	}
	current := BuildPlanWithDefense(finding, DefenseGuidanceContext{
		RetestID:            6,
		RetestStatus:        "completed",
		RetestVerdict:       "reproduced",
		ScenarioState:       "current",
		ScenarioStageTitles: []string{"비정상 JSON 요청", "500 오류 응답"},
		ExecutionID:         "6",
		ExecutionState:      "current",
		ExecutionDetection:  "missed",
		ExecutionPrevention: "not_blocked",
	})
	if len(current.VerifiedFacts) != 2 || len(current.ScenarioAssumptions) != 2 || len(current.ContextWarnings) != 0 {
		t.Fatalf("current defense inputs lost: %+v", current)
	}
	if !strings.Contains(current.VerifiedFacts[1].Text, "과거 침해 여부의 증거가 아닙니다") {
		t.Fatal("current defense verdict was presented as historical compromise")
	}
}

func TestPlanRejectsUnsafeRouteAndIncompleteRetest(t *testing.T) {
	plan := BuildPlanWithDefense(FindingContext{Name: "CWE-209 오류 정보 노출"}, DefenseGuidanceContext{
		SuggestedPath: "/safe\n외부 지시",
		RetestID:      9,
		RetestStatus:  "failed",
		RetestVerdict: "reproduced",
	})
	if len(plan.VerifiedFacts) != 0 || len(plan.ContextWarnings) == 0 || strings.Contains(plan.Hypotheses[0].Statement, "/safe") {
		t.Fatal("unsafe path or unfinished retest entered verified guidance")
	}
}
func TestScopeAndBoundary(t *testing.T) {
	s := testScope()
	if e := ValidateScope(s, s.End); e != nil {
		t.Fatal(e)
	}
	s.End = s.Start.Add(32 * 24 * time.Hour)
	if ValidateScope(s, s.End) == nil {
		t.Fatal("31 day limit")
	}
	s = testScope()
	s.Target = "https://juice-shop/"
	if ValidateScope(s, time.Now()) == nil {
		t.Fatal("URL scope allowed")
	}
	for _, tt := range []struct {
		event, scope string
		want         bool
	}{{"http://EXAMPLE.test/a", "example.test:80", true}, {"https://example.test/a", "example.test:443", true}, {"example.test", "example.test:443", false}, {"evil-example.test", "example.test", false}, {"example.test:90", "example.test", true}, {"user@example.test", "example.test", false}} {
		if got := MatchTarget(tt.event, tt.scope); got != tt.want {
			t.Errorf("target %q %q=%v", tt.event, tt.scope, got)
		}
	}
	for _, tt := range []struct {
		path string
		want bool
	}{{"/ftp", true}, {"/ftp/a?next=1", true}, {"/ftp-other", false}, {"/ftp%2Fa", true}, {"/ftp%252Fa", false}, {"http://juice-shop:3000/ftp/a?q=x", true}} {
		if got := MatchPath(tt.path, "/ftp"); got != tt.want {
			t.Errorf("path %q=%v", tt.path, got)
		}
	}
}

func TestSplunkExportTimeKeepsOffsetPrecisionAndWindow(t *testing.T) {
	want := time.Date(2026, 1, 1, 0, 5, 0, 123456000, time.UTC)
	for _, value := range []string{"2026-01-01T09:05:00.123456+0900", "2025-12-31T17:05:00.123456-0700", "2026-01-01T00:05:00.123456+0000"} {
		c := parse(t, row("export-time", "/ftp/a", map[string]any{"timestamp": value}))
		if !c.Complete || len(c.Events) != 1 || !c.Events[0].Timestamp.Equal(want) {
			t.Fatal("numeric export offset or microseconds changed the selected evidence")
		}
	}
	for _, value := range []string{"2026-01-01T08:59:59.999999+0900", "2026-01-01T10:00:00.000000+0900"} {
		c := parse(t, row("outside-export-time", "/ftp/a", map[string]any{"timestamp": value}))
		if len(c.Events) != 0 || c.Stats.OutsideWindow != 1 {
			t.Fatal("numeric export offset moved a row into the historical window")
		}
	}
	for _, value := range []any{"2026-01-01 09:05:00.123 KST", []string{"2026-01-01T09:05:00.123456+0900", "2026-01-01T09:06:00.123456+0900"}} {
		c := parse(t, row("ambiguous-export-time", "/ftp/a", map[string]any{"timestamp": value}))
		if c.Complete || len(c.Events) != 0 || c.Stats.InvalidEvents != 1 {
			t.Fatal("ambiguous or conflicting export timestamps produced complete evidence")
		}
	}
}
func TestOriginalEvidenceAndUniqueArrayRefs(t *testing.T) {
	content := "[" + row("duplicate", "/ftp/a", nil) + "," + row("duplicate", "/ftp/b", nil) + "]"
	c := parse(t, content)
	if len(c.Events) != 2 || c.Events[0].Ref == c.Events[1].Ref {
		t.Fatalf("bad refs %+v", c.Events)
	}
	sum := sha256.Sum256([]byte(content))
	if c.Files[0].Content != content || c.Files[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("original lost")
	}
	if c.Events[0].Line != 1 || !strings.Contains(c.Events[1].Raw, "/ftp/b") {
		t.Fatal("raw location lost")
	}
}
func TestMissingTargetNeedsAttestationAndWrongTargetCannotOverride(t *testing.T) {
	r := row("x", "/ftp", map[string]any{"target": nil})
	c := parse(t, r)
	if c.Complete || len(c.Events) != 0 || c.Stats.MissingTarget != 1 {
		t.Fatal("missing target accepted", c)
	}
	c, e := ParseFiles([]InputFile{{Name: "a.jsonl", Content: r}}, testScope(), DefaultMapping(), true, true, nil)
	if e != nil || !c.Complete || len(c.Events) != 1 {
		t.Fatal("attested target rejected", e, c)
	}
	r = row("x", "/ftp", map[string]any{"target": "other:3000"})
	c, e = ParseFiles([]InputFile{{Name: "a.jsonl", Content: r}}, testScope(), DefaultMapping(), true, true, nil)
	if e != nil || len(c.Events) != 0 || c.Stats.UnrelatedTarget != 1 {
		t.Fatal("attestation overrode actual target")
	}
}
func TestRejectAmbiguousMalformedInputs(t *testing.T) {
	for _, f := range []InputFile{{"a.jsonl", `{"x":1,"x":2}`}, {"a.jsonl", `{"x":{"y":1,"y":2}}`}, {"a.jsonl", "{bad}"}, {"a.jsonl", string([]byte{255})}, {"a.csv", "timestamp,timestamp\na,b\n"}, {"a.json", "[{\"x\":1}] true"}, {"a.jsonl", `{"x":` + strings.Repeat("[", 66) + `0` + strings.Repeat("]", 66) + `}`}} {
		if _, e := ParseFiles([]InputFile{f}, testScope(), DefaultMapping(), true, false, nil); e == nil {
			t.Errorf("accepted %q", f)
		}
	}
}
func TestInvalidRowsCannotProduceFalseClean(t *testing.T) {
	for _, extra := range []map[string]any{{"timestamp": "2026-01-01 00:05:00"}, {"timestamp": "NaN"}, {"path": 42}, {"target": 42}, {"target": "[bad"}, {"bytes": -1}, {"response_complete": "maybe"}, {"session": []string{"a", "b"}}} {
		c := parse(t, row("x", "/ftp", extra))
		if c.Complete || c.Stats.InvalidEvents != 1 {
			t.Fatal("invalid row considered complete", extra, c)
		}
		a := Analyze(plan(), testScope(), c)
		if a.Hypotheses[0].Status != "insufficient_data" {
			t.Fatal("false clean", a)
		}
	}
}
func TestWindowFilteringAndEmptyComplete(t *testing.T) {
	c := parse(t, row("x", "/ftp", map[string]any{"timestamp": "2026-01-01T01:00:00Z"})+"\n"+row("y", "/other", nil))
	if c.Stats.OutsideWindow != 1 || c.Stats.UnrelatedPath != 1 || len(c.Events) != 0 {
		t.Fatal(c)
	}
	a := Analyze(plan(), testScope(), c)
	if a.Hypotheses[0].Status != "not_observed" {
		t.Fatal(a)
	}
	c = parse(t, "")
	if !c.Complete || len(c.Files) != 1 || len(c.Events) != 0 {
		t.Fatal(c)
	}
	c.CoverageConfirmed = false
	c.Complete = false
	if Analyze(plan(), testScope(), c).Hypotheses[0].Status != "insufficient_data" {
		t.Fatal("missing coverage")
	}
}
func TestKnownARTEXRequiresKnownExactMarker(t *testing.T) {
	content := row("a", "/ftp/a", map[string]any{"artex_verification_id": "known-id"}) + "\n" + row("b", "/ftp/b", map[string]any{"artex_verification_id": "unknown-id"})
	c, e := ParseFiles([]InputFile{{Name: "a.jsonl", Content: content}}, testScope(), DefaultMapping(), true, false, []string{"known-id"})
	if e != nil {
		t.Fatal(e)
	}
	a := Analyze(plan(), testScope(), c)
	if a.KnownARTEXCount != 1 || a.ObservedCount != 1 || len(a.Hypotheses[0].EvidenceRefs) != 1 || c.Stats.UnrecognizedMarkers != 1 {
		t.Fatal(c, a)
	}
	if a.Hypotheses[1].Status == "suspicious" {
		t.Fatal("known test joined suspect flow")
	}
}
func TestSequencesSeparateSourcesAndDoNotClaimCompromise(t *testing.T) {
	c := parse(t, row("a", "/ftp/a", nil)+"\n"+row("b", "/ftp/b", nil))
	a := Analyze(plan(), testScope(), c)
	if a.Hypotheses[1].Status != "suspicious" || len(a.Signals) != 1 {
		t.Fatal(a)
	}
	if a.Hypotheses[2].Status != "manual_review" || len(a.Hypotheses[2].EvidenceRefs) != 0 {
		t.Fatal("credentials inferred", a)
	}
	c, e := ParseFiles([]InputFile{{Name: "one.jsonl", Content: row("a", "/ftp/a", nil)}, {Name: "two.jsonl", Content: row("b", "/ftp/b", nil)}}, testScope(), DefaultMapping(), true, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(Analyze(plan(), testScope(), c).Signals) != 0 {
		t.Fatal("cross-file same IP falsely joined")
	}
	c = parse(t, row("a", "/ftp/a", map[string]any{"sourcetype": "web"})+"\n"+row("b", "/ftp/b", map[string]any{"sourcetype": "alert"}))
	if len(Analyze(plan(), testScope(), c).Signals) != 0 {
		t.Fatal("cross-sourcetype same IP falsely joined")
	}
	c = parse(t, row("a", "/ftp/a", map[string]any{"host": "sensor-a"})+"\n"+row("b", "/ftp/b", map[string]any{"host": "sensor-b"}))
	if len(Analyze(plan(), testScope(), c).Signals) != 0 {
		t.Fatal("cross-sensor same IP falsely joined")
	}
}
func TestSequenceTimeAndAlertExclusion(t *testing.T) {
	for _, extra := range []map[string]any{{"timestamp": "2026-01-01T00:16:00Z"}, {"event_kind": "alert"}, {"id": "a"}} {
		c := parse(t, row("a", "/ftp/a", nil)+"\n"+row("b", "/ftp/b", extra))
		if len(Analyze(plan(), testScope(), c).Signals) != 0 {
			t.Fatal("false flow", extra)
		}
	}
}
func TestCSVAndSplunkRawFallback(t *testing.T) {
	csv := "timestamp,target,path,id,source_ip\n2026-01-01T00:05:00Z,juice-shop:3000,/ftp/a,1,192.0.2.1\n"
	c, e := ParseFiles([]InputFile{{Name: "access.csv", Content: csv}}, testScope(), DefaultMapping(), true, false, nil)
	if e != nil || len(c.Events) != 1 || c.Events[0].Line != 2 {
		t.Fatal(e, c)
	}
	raw := row("raw-id", "/ftp/a", nil)
	outer, _ := json.Marshal(map[string]any{"_time": "1767225900.25", "_raw": raw, "path": "/ftp/top"})
	m := DefaultMapping()
	m.Timestamp = "_time"
	c, e = ParseFiles([]InputFile{{Name: "splunk.jsonl", Content: string(outer)}}, testScope(), m, true, false, nil)
	if e != nil || len(c.Events) != 1 || c.Events[0].Path != "/ftp/top" || c.Events[0].ID != "raw-id" || c.Events[0].Timestamp.Nanosecond() != 250000000 {
		t.Fatal(e, c)
	}
}

func TestSourceMetadataCollisionPreservesEvidenceWithoutJoiningOrigins(t *testing.T) {
	rows := []string{}
	for i, path := range []string{"/ftp/a", "/ftp/b", "/ftp/c"} {
		rows = append(rows, row(fmt.Sprint(i), path, map[string]any{
			"source": []string{"modsecurity-native", "modsecurity-native-audit"},
			"host":   "sensor-a", "sourcetype": "waf:audit",
		}))
	}
	c := parse(t, strings.Join(rows, "\n"))
	if len(c.Events) != 3 || c.Stats.InvalidEvents != 0 || c.Complete {
		t.Fatalf("ambiguous provenance lost evidence or claimed completeness: %+v", c.Stats)
	}
	for _, e := range c.Events {
		if !e.SourceAmbiguous || !strings.Contains(e.Raw, `"modsecurity-native-audit"`) {
			t.Fatal("source conflict or original evidence lost")
		}
	}
	if c.Events[0].Source == c.Events[1].Source || len(Analyze(plan(), testScope(), c).Signals) != 0 {
		t.Fatal("ambiguous source was used to join independent events")
	}
	warnings := 0
	for _, warning := range c.Warnings {
		if strings.Contains(warning, "서로 다른 출처") {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatal("source conflicts should produce one collection warning")
	}
}

func TestSourceMetadataDuplicatesAndMalformedValues(t *testing.T) {
	plain := parse(t, row("same", "/ftp/a", map[string]any{"source": "sensor-a"}))
	duplicate := parse(t, row("same", "/ftp/a", map[string]any{"source": []string{"sensor-a", "sensor-a"}}))
	if !duplicate.Complete || len(duplicate.Events) != 1 || duplicate.Events[0].SourceAmbiguous || duplicate.Events[0].Source != plain.Events[0].Source {
		t.Fatal("equal source duplicates changed source identity")
	}
	for _, value := range []any{[]any{}, []any{"sensor-a", 7}, map[string]any{"name": "sensor-a"}} {
		c := parse(t, row("invalid", "/ftp/a", map[string]any{"source": value}))
		if c.Complete || len(c.Events) != 0 || c.Stats.InvalidEvents != 1 {
			t.Fatal("malformed provenance accepted")
		}
	}
}
func TestDottedLiteralKeyPrecedence(t *testing.T) {
	m := DefaultMapping()
	m.Path = "http.path"
	c, e := ParseFiles([]InputFile{{Name: "a.jsonl", Content: row("x", "/other", map[string]any{"http.path": "/ftp/literal", "http": map[string]any{"path": "/other"}})}}, testScope(), m, true, false, nil)
	if e != nil || len(c.Events) != 1 || c.Events[0].Path != "/ftp/literal" {
		t.Fatal(e, c)
	}
}
func TestBoundsExplicitAndUnmappedPathInsufficient(t *testing.T) {
	rows := make([]string, MaxEvents+1)
	for i := range rows {
		rows[i] = row(fmt.Sprint(i), "/ftp/a", nil)
	}
	c := parse(t, strings.Join(rows, "\n"))
	if c.Complete || len(c.Events) != MaxEvents || c.Stats.Truncated != 1 {
		t.Fatal("silent truncation", c.Stats)
	}
	m := DefaultMapping()
	m.Path = ""
	s := testScope()
	s.PathPrefix = ""
	c, e := ParseFiles([]InputFile{{Name: "a.jsonl", Content: row("a", "/ftp", nil)}}, s, m, true, false, nil)
	if e != nil {
		t.Fatal(e)
	}
	if Analyze(plan(), s, c).Hypotheses[0].Status != "insufficient_data" {
		t.Fatal("unmapped path observed")
	}
	m.Path = m.Timestamp
	if ValidateMapping(m) == nil {
		t.Fatal("ambiguous mapping")
	}
}
func TestTimelineSortedAndEveryRefExists(t *testing.T) {
	c := parse(t, row("later", "/ftp/b", map[string]any{"timestamp": "2026-01-01T00:06:00Z"})+"\n"+row("earlier", "/ftp/a", nil))
	a := Analyze(plan(), testScope(), c)
	if a.Timeline[0].EventID != "earlier" {
		t.Fatal("unsorted")
	}
	refs := map[string]bool{}
	for _, e := range c.Events {
		refs[e.Ref] = true
	}
	for _, h := range a.Hypotheses {
		for _, ref := range h.EvidenceRefs {
			if !refs[ref] {
				t.Fatal("ungrounded ref", ref)
			}
		}
	}
}
