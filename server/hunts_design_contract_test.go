package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/hunting"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/norma/llm"
)

type huntDesignContractProvider struct {
	design  hunting.Design
	request llm.CompletionRequest
	calls   int
}

func (p *huntDesignContractProvider) Complete(_ context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	p.request = request
	raw, err := json.Marshal(p.design)
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(string(raw))}}, "end_turn", llm.Usage{}, err
}

func (*huntDesignContractProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	panic("design generation must use one Complete call")
}

func huntDesignContractFixture(t *testing.T) (hunting.Request, hunting.Research, hunting.Design) {
	t.Helper()
	now := time.Now().UTC()
	request := hunting.Request{Term: "php2shell", SourceID: 1, ExpectedSourceRevision: 1, Mapping: investigation.DefaultMapping(), ResearchURLs: []string{"https://research.example.com/php2shell"}, Scope: investigation.Scope{Target: "lab.example", Start: now.Add(-time.Hour), End: now.Add(-time.Minute)}}
	// Reuse the in-memory literature transport; no external lookup is made.
	research, err := huntTestResearcher().Run(t.Context(), request)
	if err != nil || hunting.ValidateResearch(request, research) != nil {
		t.Fatalf("invalid research fixture: %v", err)
	}
	source := []string{research.Sources[0].ID}
	design := hunting.Design{Title: "PHP2Shell 최소 증거 계약", Summary: "인벤토리와 웹 요청은 독립 조사하고 실행 영향은 직접 근거를 요구합니다.", Stages: []hunting.Stage{
		{ID: "inventory", AttackDescription: "가정: 영향 버전·구성이 존재할 수 있습니다.", DetectionQuestion: "PHP 버전·SAPI·모듈 구성이 확인되는가?", RequiredFields: []string{"target", "php.version", "php.sapi", "php.modules"}, SuccessCriteria: "배포 인벤토리 원문에서 버전과 구성을 확인합니다.", BenignAlternatives: []string{"패치된 버전 또는 영향 없는 구성"}, SourceIDs: source},
		{ID: "web", AttackDescription: "가정: 관련 요청이 대상 웹 서비스에 도달했을 수 있습니다.", DetectionQuestion: "허용 시간대에 의심 요청과 연관된 웹 활동이 있는가?", RequiredFields: []string{"timestamp", "target", "path", "source_ip", "action", "status", "event_kind", "response_complete"}, SuccessCriteria: "대상·시각·요청 원문을 대조하고 HTTP 상태만으로 악용 성공을 단정하지 않습니다.", BenignAlternatives: []string{"정상 상태 점검", "승인된 테스트"}, SourceIDs: source},
		{ID: "impact", AttackDescription: "가정: 요청 이후 PHP 자식 프로세스 실행이 있었을 수 있습니다.", DetectionQuestion: "의심 요청과 연결되는 PHP 자식 프로세스 실행이 있는가?", RequiredFields: []string{"timestamp", "target", "process_command", "parent_process", "process.pid", "process.user", "process.start_time", "request.id"}, SuccessCriteria: "요청과 연결된 호스트 프로세스 실행의 직접 원문이 필요합니다.", BenignAlternatives: []string{"정상 유지보수 작업"}, SourceIDs: source, DependsOn: []string{"web"}},
	}}
	return request, research, design
}

func TestHuntDesignContractSendsBoundsAndIndependentActivityInstructions(t *testing.T) {
	request, research, design := huntDesignContractFixture(t)
	provider := &huntDesignContractProvider{design: design}
	if _, err := generateHuntDesign(t.Context(), provider, request, research); err != nil {
		t.Fatal(err)
	}
	prompt := strings.Join(provider.request.System, "\n")
	for _, required := range []string{
		"title 1~200자", "summary 1~4000자", "stages 1~4개", "각각 1~2000자",
		"required_fields는 중복 없는 1~16개", "각각 1~100자", "^[A-Za-z_][A-Za-z0-9_.-]{0,99}$",
		"benign_alternatives는 중복 없는 1~8개", "각각 1~1000자", "source_ids는 입력 출처에 실제 존재하는 ID를 중복 없이 1~8개",
		"event_kinds는 중복 없는 0~12개", "각각 1~128자", "path_contains는 중복 없는 0~12개", "각각 1~256자",
		"depends_on은 앞선 단계의 고유 ID만 중복 없이 0~3개", "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$",
		"보통 4~8개", "UTF-8 2000바이트", "미지원 필드가 정말 필요한 질문에서는 그 필드를 보존",
		"웹 활동 단계는 인벤토리 단계에 depends_on을 걸지 말고", "실제 영향 단계에만 사용",
	} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("outgoing model contract omitted %q", required)
		}
	}
	if provider.calls != 1 || provider.request.MaxTokens != 6000 {
		t.Fatal("contract update introduced a retry or changed the output budget")
	}
}

func TestHuntDesignContractRejectsTwentyThreeFieldsWithoutRepairOrDropping(t *testing.T) {
	request, research, design := huntDesignContractFixture(t)
	fields := []string{"timestamp", "target", "path", "source_ip", "action", "status", "event_kind", "response_complete", "user", "session", "bytes", "event_id", "http.method", "http.user_agent", "http.content_type", "http.request_length", "http.response_length", "http.headers.content_length", "http.body", "process_command", "parent_process", "php.version", "php.sapi"}
	design.Stages[1].RequiredFields = append([]string{}, fields...)
	provider := &huntDesignContractProvider{design: design}
	investigated := false
	result, err := hunting.Run(t.Context(), request, hunting.Dependencies{
		Research: func(context.Context, hunting.Request) (hunting.Research, error) { return research, nil },
		Design: func(ctx context.Context, req hunting.Request, facts hunting.Research) (hunting.Design, error) {
			return generateHuntDesign(ctx, provider, req, facts)
		},
		Investigate: func(context.Context, hunting.Request, hunting.Design, func(hunting.Event) error) (hunting.InvestigationResult, error) {
			investigated = true
			return hunting.InvestigationResult{}, nil
		},
	})
	if !errors.Is(err, hunting.ErrInvalid) || result.Status != "failed" || result.Stage != "design" || investigated || provider.calls != 1 {
		t.Fatalf("oversized design reached investigation or paid repair: status=%s stage=%s calls=%d err=%v", result.Status, result.Stage, provider.calls, err)
	}
	if len(result.Design.Stages[1].RequiredFields) != 23 || !reflect.DeepEqual(result.Design.Stages[1].RequiredFields, fields) || !reflect.DeepEqual(provider.design.Stages[1].RequiredFields, fields) {
		t.Fatal("invalid model requirements were silently truncated or dropped")
	}
}

func TestHuntDesignContractEightFieldsReachInvestigationAndVerification(t *testing.T) {
	request, research, design := huntDesignContractFixture(t)
	provider := &huntDesignContractProvider{design: design}
	investigated := false
	result, err := hunting.Run(t.Context(), request, hunting.Dependencies{
		Research: func(context.Context, hunting.Request) (hunting.Research, error) { return research, nil },
		Design: func(ctx context.Context, req hunting.Request, facts hunting.Research) (hunting.Design, error) {
			return generateHuntDesign(ctx, provider, req, facts)
		},
		Investigate: func(_ context.Context, _ hunting.Request, received hunting.Design, _ func(hunting.Event) error) (hunting.InvestigationResult, error) {
			investigated = true
			if len(received.Stages[1].RequiredFields) != 8 || len(received.Stages[1].DependsOn) != 0 || !reflect.DeepEqual(received.Stages[2].DependsOn, []string{"web"}) {
				t.Fatal("web activity was gated on unavailable inventory or impact lost its dependency")
			}
			for _, stage := range received.Stages {
				question, shortened, contractErr := huntStageQuestion(stage, nil)
				var view huntStageContext
				if contractErr != nil || shortened || len(question) > huntStageContextBytes || json.Unmarshal([]byte(question), &view) != nil || !reflect.DeepEqual(view.RequiredFields, stage.RequiredFields) {
					t.Fatalf("concise stage lost fields at execution boundary: stage=%s bytes=%d err=%v", stage.ID, len(question), contractErr)
				}
			}
			return hunting.InvestigationResult{Status: "insufficient_data", Summary: "계약 테스트에는 실제 텔레메트리를 제공하지 않았습니다."}, nil
		},
	})
	if err != nil || !investigated || provider.calls != 1 || result.Stage != "verification" || result.Status != "insufficient_data" || len(result.Verification.Stages) != len(design.Stages) {
		t.Fatalf("valid concise design did not reach all phases: status=%s stage=%s calls=%d err=%v", result.Status, result.Stage, provider.calls, err)
	}
	if !reflect.DeepEqual(result.Design.Stages[2].RequiredFields, design.Stages[2].RequiredFields) || result.Verification.Stages[2].Status != "insufficient_data" || result.Verification.ImpactConfirmed {
		t.Fatal("missing host fields were dropped or converted into a positive observation")
	}
}
