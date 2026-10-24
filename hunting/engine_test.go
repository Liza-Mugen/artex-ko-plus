package hunting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

func testRequest() Request {
	now := time.Now().UTC().Truncate(time.Second)
	return Request{Term: "php2shell", SourceID: 1, ExpectedSourceRevision: 2, Scope: investigation.Scope{Target: "lab.example", PathPrefix: "/", Start: now.Add(-3 * time.Hour), End: now.Add(-time.Hour)}, Mapping: investigation.DefaultMapping()}
}

func testResearch(req Request) Research {
	excerpt := "This retained reference describes a possible PHP request and subsequent host activity, not an observed incident."
	sum := sha256.Sum256([]byte(excerpt))
	return Research{Term: req.Term, Summary: "출처의 행동 설명을 확인하고 제품명·공격 발생 주장을 구분합니다.", Sources: []ResearchSource{{ID: "source-1", URL: "https://example.org/reference", Title: "Research fixture", Excerpt: excerpt, SHA256: hex.EncodeToString(sum[:]), FetchedAt: time.Now().UTC()}}, Claims: []ResearchClaim{{Text: "PHP 관련 행동의 과거 관측을 원본 로그로 조사할 수 있습니다.", SourceIDs: []string{"source-1"}}}}
}

func testDesign() Design {
	return Design{Title: "독립 PHP 활동 헌팅", Summary: "공격 가능성을 가정하고 실제 과거 활동 근거와 정상 대안을 검토합니다.", Stages: []Stage{{ID: "stage-1", AttackDescription: "PHP 경로 요청 이후의 행동이 있었을 가능성", DetectionQuestion: "해당 경로의 요청 활동이 기록되었는가?", RequiredFields: []string{"timestamp", "target", "path", "event_kind"}, SuccessCriteria: "원본에서 대상·시각·경로·이벤트 종류를 확인합니다.", BenignAlternatives: []string{"정상 PHP 페이지 이용", "승인된 점검"}, SourceIDs: []string{"source-1"}, EventKinds: []string{"web"}, PathContains: []string{".php"}}}}
}

func testInvestigation(req Request) InvestigationResult {
	mapping := req.Mapping
	mapping.Timestamp = "_time"
	event := investigation.Event{Ref: "sha256:source:1", ID: "event-1", Timestamp: req.Scope.Start.Add(time.Minute), Target: req.Scope.Target, Path: "/index.php", EventKind: "web", FileName: "splunk-events.jsonl", Source: "web-access", Line: 1, Raw: `{"target":"lab.example","path":"/index.php","event_kind":"web","status":200}`}
	collection := investigation.Collection{SourceKind: "splunk", CollectedAt: time.Now().UTC(), Scope: req.Scope, Mapping: mapping, Complete: true, CoverageConfirmed: true, Events: []investigation.Event{event}, Stats: investigation.Stats{Selected: 1}}
	return InvestigationResult{Status: "completed", Summary: "실제 저장된 원문으로 관측했습니다.", ScopeCoverageConfirmed: true, Collections: []investigation.Collection{collection}, Observations: []Observation{{StageID: "stage-1", Kind: "observed", Summary: "대상 경로의 웹 요청이 기록됐습니다. 코드 실행을 뜻하지 않습니다.", EvidenceRefs: []string{event.Ref}}}, Usage: Usage{ModelCalls: 2, Queries: 1, RemoteQueries: 1}}
}

func testDependencies() Dependencies {
	return Dependencies{
		Research: func(_ context.Context, req Request) (Research, error) { return testResearch(req), nil },
		Design:   func(_ context.Context, _ Request, _ Research) (Design, error) { return testDesign(), nil },
		Investigate: func(_ context.Context, req Request, _ Design, _ func(Event) error) (InvestigationResult, error) {
			return testInvestigation(req), nil
		},
	}
}

func TestRunIndependentFourPhasesPreserveResearchAndDesignSnapshots(t *testing.T) {
	var persisted []Event
	deps := testDependencies()
	deps.Emit = func(event Event) error { persisted = append(persisted, event); return nil }
	result, err := Run(context.Background(), testRequest(), deps)
	if err != nil || result.Status != "completed" || result.Verification.Stages[0].Status != "evidence_observed" || result.Verification.ImpactConfirmed {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || len(persisted) != len(result.Events) {
		t.Fatal("runtime times or persisted events missing")
	}
	for i, event := range result.Events {
		if event.Sequence != int64(i+1) || event.At.IsZero() {
			t.Fatal("event order is not durable and explicit")
		}
	}
	var research, design bool
	for _, event := range persisted {
		switch event.Kind {
		case "research_completed":
			var snapshot Research
			if json.Unmarshal(event.Payload, &snapshot) != nil || len(snapshot.Sources) != 1 || snapshot.Sources[0].SHA256 == "" {
				t.Fatal("research snapshot missing")
			}
			research = true
		case "design_completed":
			var snapshot Design
			if json.Unmarshal(event.Payload, &snapshot) != nil || snapshot.Stages[0].SourceIDs[0] != "source-1" {
				t.Fatal("design provenance missing")
			}
			design = true
		}
	}
	if !research || !design {
		t.Fatal("phase snapshots were not preserved before querying")
	}
}

func TestRunRejectsResearchProvenanceBeforeModelOrLogWork(t *testing.T) {
	deps := testDependencies()
	deps.Research = func(_ context.Context, req Request) (Research, error) {
		r := testResearch(req)
		r.Sources[0].Excerpt += "changed"
		return r, nil
	}
	deps.Design = func(context.Context, Request, Research) (Design, error) {
		t.Fatal("paid generation ran with invalid research")
		return Design{}, nil
	}
	result, err := Run(context.Background(), testRequest(), deps)
	if !errors.Is(err, ErrInvalid) || result.Status != "failed" || result.Stage != "research" || len(result.Research.Sources) == 0 {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestRunPersistenceFailureStopsFurtherWorkAndRetainsTerminal(t *testing.T) {
	deps := testDependencies()
	failure := errors.New("test durable store unavailable")
	deps.Emit = func(event Event) error {
		if event.Kind == "research_completed" {
			return failure
		}
		return nil
	}
	deps.Design = func(context.Context, Request, Research) (Design, error) {
		t.Fatal("generation continued after failed evidence preservation")
		return Design{}, nil
	}
	result, err := Run(context.Background(), testRequest(), deps)
	if !errors.Is(err, failure) || result.Status != "interrupted" || result.Events[len(result.Events)-1].Kind != "finished" || len(result.Research.Sources) == 0 {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestRunPreservesVerifiedPartialEvidenceWithoutConvertingFailureToSuccess(t *testing.T) {
	deps := testDependencies()
	failure := errors.New("model failed after observing real evidence")
	deps.Investigate = func(_ context.Context, req Request, _ Design, _ func(Event) error) (InvestigationResult, error) {
		partial := testInvestigation(req)
		partial.Status = "model_error"
		return partial, failure
	}
	out, err := Run(context.Background(), testRequest(), deps)
	if !errors.Is(err, failure) || out.Status != "model_error" || len(out.Investigation.Collections) != 1 || out.Verification.Stages[0].Status != "evidence_observed" || out.Verification.ImpactConfirmed {
		t.Fatalf("partial evidence lost or failure rewritten: %+v %v", out, err)
	}
	var receipt bool
	for _, event := range out.Events {
		receipt = receipt || event.Kind == "partial_verification"
	}
	if !receipt {
		t.Fatal("partial verdict was not preserved as an ordered event")
	}

	deps.Investigate = func(_ context.Context, req Request, _ Design, _ func(Event) error) (InvestigationResult, error) {
		partial := testInvestigation(req)
		partial.Status = "interrupted"
		partial.Observations[0].EvidenceRefs = []string{"uncollected"}
		return partial, failure
	}
	out, err = Run(context.Background(), testRequest(), deps)
	if !errors.Is(err, failure) || out.Status != "interrupted" || out.Verification.Stages[0].Status != "insufficient_data" || out.Verification.Stages[0].RejectedObservations != 1 {
		t.Fatalf("invalid partial reference accepted: %+v %v", out, err)
	}
}

func TestRunCancelledAndBudgetedDoNotRetryPaidCallbacks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := testDependencies()
	deps.Research = func(context.Context, Request) (Research, error) {
		t.Fatal("research ran after cancellation")
		return Research{}, nil
	}
	result, err := Run(ctx, testRequest(), deps)
	if !errors.Is(err, context.Canceled) || result.Status != "cancelled" {
		t.Fatalf("%+v %v", result, err)
	}

	deps = testDependencies()
	calls := 0
	deps.Investigate = func(_ context.Context, req Request, _ Design, _ func(Event) error) (InvestigationResult, error) {
		calls++
		r := testInvestigation(req)
		r.Status = "budget_exhausted"
		return r, nil
	}
	result, err = Run(context.Background(), testRequest(), deps)
	if err != nil || calls != 1 || result.Status != "budget_exhausted" || result.Verification.Stages[0].Status != "evidence_observed" {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestRunRejectsLateEventsAndLimitsEventFlood(t *testing.T) {
	deps := testDependencies()
	var late func(Event) error
	deps.Investigate = func(_ context.Context, req Request, _ Design, emit func(Event) error) (InvestigationResult, error) {
		late = emit
		return testInvestigation(req), nil
	}
	result, err := Run(context.Background(), testRequest(), deps)
	if err != nil {
		t.Fatal(err)
	}
	count := len(result.Events)
	if !errors.Is(late(Event{Stage: "investigation", Kind: "progress", Summary: "late"}), ErrRunClosed) || len(result.Events) != count {
		t.Fatal("late callbacks changed a terminal run")
	}

	deps.Investigate = func(_ context.Context, req Request, _ Design, emit func(Event) error) (InvestigationResult, error) {
		for i := 0; i < MaxEvents+10; i++ {
			if err := emit(Event{Stage: "investigation", Kind: "progress", Summary: "bounded progress"}); err != nil {
				return testInvestigation(req), err
			}
		}
		return testInvestigation(req), nil
	}
	result, err = Run(context.Background(), testRequest(), deps)
	if !errors.Is(err, ErrBudget) || result.Status != "budget_exhausted" || len(result.Events) > MaxEvents || result.Events[len(result.Events)-1].Kind != "finished" {
		t.Fatalf("events=%d status=%s err=%v", len(result.Events), result.Status, err)
	}
}

func TestRunPreservesLargerEvidenceCollectionsButBoundsProgressPayloads(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"raw": strings.Repeat("x", 300<<10)})
	deps := testDependencies()
	deps.Investigate = func(_ context.Context, req Request, _ Design, emit func(Event) error) (InvestigationResult, error) {
		err := emit(Event{Stage: "investigation", Kind: "evidence_collection", Summary: "실제 근거 보존", Payload: payload})
		return testInvestigation(req), err
	}
	out, err := Run(context.Background(), testRequest(), deps)
	if err != nil || out.Status != "completed" {
		t.Fatalf("bootstrap evidence was truncated: %s %v", out.Status, err)
	}
	deps.Investigate = func(_ context.Context, req Request, _ Design, emit func(Event) error) (InvestigationResult, error) {
		err := emit(Event{Stage: "investigation", Kind: "progress", Summary: "progress is not an evidence artifact", Payload: payload})
		return testInvestigation(req), err
	}
	out, err = Run(context.Background(), testRequest(), deps)
	if !errors.Is(err, ErrBudget) || out.Status != "budget_exhausted" {
		t.Fatalf("progress payload was not bounded: %s %v", out.Status, err)
	}
}

func TestValidateDesignRejectsInventedSourcesAndCyclicStageGraph(t *testing.T) {
	req := testRequest()
	design := testDesign()
	design.Stages[0].SourceIDs = []string{"invented"}
	if !errors.Is(ValidateDesign(design, testResearch(req)), ErrInvalid) {
		t.Fatal("invented provenance accepted")
	}
	design = testDesign()
	next := design.Stages[0]
	next.ID, next.DependsOn = "stage-2", []string{"stage-1"}
	design.Stages[0].DependsOn = []string{"stage-2"}
	design.Stages = append(design.Stages, next)
	if !errors.Is(ValidateDesign(design, testResearch(req)), ErrInvalid) {
		t.Fatal("cyclic dependency accepted")
	}
	design.Stages[0].DependsOn = nil
	if err := ValidateDesign(design, testResearch(req)); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeRequestRequiresBoundedSourceAndDoesNotMutateInput(t *testing.T) {
	req := testRequest()
	req.Mapping = investigation.Mapping{}
	req.ResearchURLs = []string{"https://example.org/advisory"}
	normalized, err := NormalizeRequest(req)
	if err != nil || normalized.Mapping != investigation.DefaultMapping() || req.Mapping != (investigation.Mapping{}) {
		t.Fatal("mapping default mutated the input")
	}
	normalized.ResearchURLs[0] = "https://example.org/changed"
	if req.ResearchURLs[0] != "https://example.org/advisory" {
		t.Fatal("URL input slice was shared")
	}
	req.ExpectedSourceRevision = 0
	if !errors.Is(ValidateRequest(req), ErrInvalid) {
		t.Fatal("missing source revision accepted")
	}
}
