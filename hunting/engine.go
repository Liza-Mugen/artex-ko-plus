package hunting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/investigation"
)

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	fieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,99}$`)
	cvePattern   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,9}$`)
)

func textValid(s string, min, max int) bool {
	n := utf8.RuneCountInString(strings.TrimSpace(s))
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && n >= min && n <= max
}

func listValid(values []string, limit, textLimit int) bool {
	if len(values) > limit {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !textValid(value, 1, textLimit) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validURL(raw string) bool {
	if len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

// NormalizeRequest provides defaults without changing the caller's slices.
// Fetch adapters still enforce URL destination/DNS policy; syntax is not trust.
func NormalizeRequest(in Request) (Request, error) {
	in.Term = strings.TrimSpace(in.Term)
	in.Sourcetypes = append([]string{}, in.Sourcetypes...)
	in.ResearchURLs = append([]string{}, in.ResearchURLs...)
	if in.Mapping == (investigation.Mapping{}) {
		in.Mapping = investigation.DefaultMapping()
	}
	if !textValid(in.Term, 1, 200) || in.SourceID <= 0 || in.ExpectedSourceRevision <= 0 || !listValid(in.Sourcetypes, 8, 128) || !listValid(in.ResearchURLs, MaxResearchSources, 2048) {
		return in, fmt.Errorf("%w: 검색어·Splunk 연결 버전·소스타입을 확인해 주세요", ErrInvalid)
	}
	for _, raw := range in.ResearchURLs {
		if !validURL(raw) {
			return in, fmt.Errorf("%w: 리서치 URL 형식을 확인해 주세요", ErrInvalid)
		}
	}
	if err := investigation.ValidateScope(in.Scope, time.Now()); err != nil {
		return in, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := investigation.ValidateMapping(in.Mapping); err != nil {
		return in, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return in, nil
}

func ValidateRequest(in Request) error {
	_, err := NormalizeRequest(in)
	return err
}

func ValidateResearch(req Request, in Research) error {
	if !strings.EqualFold(strings.TrimSpace(in.Term), strings.TrimSpace(req.Term)) || !textValid(in.Summary, 1, 4000) || len(in.Sources) < 1 || len(in.Sources) > MaxResearchSources || len(in.Claims) < 1 || len(in.Claims) > 24 || !listValid(in.Warnings, 16, 1000) || !listValid(in.CVEs, 16, 32) {
		return fmt.Errorf("%w: 출처를 확인한 리서치 요약과 주장 근거가 필요합니다", ErrInvalid)
	}
	for _, cve := range in.CVEs {
		if !cvePattern.MatchString(cve) {
			return fmt.Errorf("%w: CVE 식별자 형식이 올바르지 않습니다", ErrInvalid)
		}
	}
	sources, urls := map[string]bool{}, map[string]bool{}
	for _, source := range in.Sources {
		sum := sha256.Sum256([]byte(source.Excerpt))
		if !idPattern.MatchString(source.ID) || sources[source.ID] || urls[source.URL] || !validURL(source.URL) || !textValid(source.Title, 1, 300) || !textValid(source.Excerpt, 1, 24000) || !strings.EqualFold(source.SHA256, hex.EncodeToString(sum[:])) || source.FetchedAt.IsZero() || source.FetchedAt.After(time.Now().Add(5*time.Minute)) {
			return fmt.Errorf("%w: 리서치 출처·발췌 해시·수집 시각이 일치하지 않습니다", ErrInvalid)
		}
		sources[source.ID], urls[source.URL] = true, true
	}
	for _, claim := range in.Claims {
		if !textValid(claim.Text, 1, 1600) || len(claim.SourceIDs) == 0 || !listValid(claim.SourceIDs, MaxResearchSources, 64) {
			return fmt.Errorf("%w: 리서치 주장에 출처 참조가 필요합니다", ErrInvalid)
		}
		for _, source := range claim.SourceIDs {
			if !sources[source] {
				return fmt.Errorf("%w: 리서치 주장이 없는 출처를 인용했습니다", ErrInvalid)
			}
		}
	}
	return nil
}

// ValidateDesign checks a bounded DAG and actual research provenance. It does
// not certify the meaning of a proposed scenario or execute its prose.
func ValidateDesign(in Design, research Research) error {
	if !textValid(in.Title, 1, 200) || !textValid(in.Summary, 1, 4000) || len(in.Stages) < 1 || len(in.Stages) > MaxStages {
		return fmt.Errorf("%w: 시나리오 제목·요약·단계 수를 확인해 주세요", ErrInvalid)
	}
	sources := map[string]bool{}
	for _, source := range research.Sources {
		sources[source.ID] = true
	}
	stages := map[string]Stage{}
	for _, stage := range in.Stages {
		if !idPattern.MatchString(stage.ID) || stages[stage.ID].ID != "" || !textValid(stage.AttackDescription, 1, 2000) || !textValid(stage.DetectionQuestion, 1, 2000) || !textValid(stage.SuccessCriteria, 1, 2000) || len(stage.RequiredFields) == 0 || !listValid(stage.RequiredFields, 16, 100) || len(stage.BenignAlternatives) == 0 || !listValid(stage.BenignAlternatives, 8, 1000) || len(stage.SourceIDs) == 0 || !listValid(stage.SourceIDs, MaxResearchSources, 64) || !listValid(stage.EventKinds, 12, 128) || !listValid(stage.PathContains, 12, 256) || !listValid(stage.DependsOn, MaxStages-1, 64) {
			return fmt.Errorf("%w: 단계의 질문·필드·정상 대안·출처를 확인해 주세요", ErrInvalid)
		}
		for _, field := range stage.RequiredFields {
			if !fieldPattern.MatchString(field) {
				return fmt.Errorf("%w: 필수 필드는 실제 필드명 또는 JSON 경로로 지정해 주세요", ErrInvalid)
			}
		}
		for _, source := range stage.SourceIDs {
			if !sources[source] {
				return fmt.Errorf("%w: 시나리오 단계가 없는 리서치 출처를 인용했습니다", ErrInvalid)
			}
		}
		stages[stage.ID] = stage
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) bool
	visit = func(id string) bool {
		if visiting[id] || stages[id].ID == "" {
			return false
		}
		if visited[id] {
			return true
		}
		visiting[id] = true
		for _, dependency := range stages[id].DependsOn {
			if !visit(dependency) {
				return false
			}
		}
		visiting[id], visited[id] = false, true
		return true
	}
	for id := range stages {
		if !visit(id) {
			return fmt.Errorf("%w: 단계 의존 관계에 순환 또는 없는 단계가 있습니다", ErrInvalid)
		}
	}
	return nil
}

// Run has four bounded phases. Duplicate submission/concurrent-run admission
// belongs to the durable API adapter; this function never retries paid phases.
func Run(parent context.Context, req Request, deps Dependencies) (Result, error) {
	out := Result{EngineVersion: EngineVersion, Status: "running", Stage: "research", StartedAt: time.Now().UTC(), Events: []Event{}}
	ctx, cancel := context.WithTimeout(parent, RunTimeout)
	defer cancel()
	var mu sync.Mutex
	var emitErr error
	eventBytes := 0
	closed := false
	emit := func(event Event) error {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return ErrRunClosed
		}
		if emitErr != nil {
			return emitErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		payloadLimit := 256 << 10
		if event.Kind == "evidence_collection" {
			payloadLimit = MaxEvidenceEventBytes
		}
		if event.Kind == "research_completed" || event.Kind == "design_completed" {
			payloadLimit = 1 << 20
		}
		if len(out.Events) >= MaxEvents-1 || len(event.Payload) > payloadLimit || !textValid(event.Summary, 1, 1000) || !textValid(event.Stage, 1, 64) || !textValid(event.Kind, 1, 64) || !textValid(event.Detail, 0, 8000) || (len(event.Payload) > 0 && !json.Valid(event.Payload)) {
			emitErr = ErrBudget
			cancel()
			return emitErr
		}
		event.Sequence, event.At = int64(len(out.Events)+1), time.Now().UTC()
		encoded, _ := json.Marshal(event)
		if eventBytes+len(encoded) > MaxEventBytes-2048 {
			emitErr = ErrBudget
			cancel()
			return emitErr
		}
		eventBytes += len(encoded)
		event.Payload = append(json.RawMessage(nil), event.Payload...)
		out.Events = append(out.Events, event)
		if deps.Emit != nil {
			if err := deps.Emit(event); err != nil {
				emitErr = err
				cancel()
				return err
			}
		}
		return nil
	}
	finish := func(status, message string, err error) (Result, error) {
		mu.Lock()
		defer mu.Unlock()
		if emitErr != nil {
			status, message, err = "interrupted", "실행 과정 보존 또는 이벤트 한도 문제로 후속 작업을 중단했습니다", emitErr
			if errors.Is(emitErr, ErrBudget) {
				status = "budget_exhausted"
			}
		} else if ctx.Err() != nil {
			status, message, err = "cancelled", "사용자 취소 또는 서비스 종료로 헌팅이 중단되었습니다", ctx.Err()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				status, message = "budget_exhausted", "헌팅 제한시간에 도달했습니다. 저장된 근거를 확인해 주세요"
			}
		}
		out.Status, out.Error, out.FinishedAt = status, message, time.Now().UTC()
		terminal := Event{Sequence: int64(len(out.Events) + 1), Stage: out.Stage, Kind: "finished", Summary: "헌팅 실행 종료: " + status, At: out.FinishedAt}
		out.Events = append(out.Events, terminal)
		closed = true
		if deps.Emit != nil && emitErr == nil {
			if saveErr := deps.Emit(terminal); saveErr != nil {
				out.Status, out.Error, err = "interrupted", "최종 실행 상태의 과정 보존에 실패했습니다", saveErr
			}
		}
		return out, err
	}
	var err error
	if req, err = NormalizeRequest(req); err != nil {
		return finish("failed", "헌팅 입력과 허용된 로그 범위를 확인해 주세요", err)
	}
	if deps.Research == nil || deps.Design == nil || deps.Investigate == nil {
		return finish("failed", "헌팅 리서치·시나리오·조사 연결이 필요합니다", ErrInvalid)
	}
	if err = emit(Event{Stage: "research", Kind: "started", Summary: "검색어의 출처를 조회하고 근거를 보존합니다"}); err != nil {
		return finish("interrupted", "리서치를 시작하지 못했습니다", err)
	}
	out.Research, err = deps.Research(ctx, req)
	if err != nil {
		return finish("failed", "리서치를 완료하지 못했습니다. 보존된 출처와 연결 상태를 확인해 주세요", err)
	}
	if err = ValidateResearch(req, out.Research); err != nil {
		return finish("failed", "리서치의 출처 또는 주장 근거를 검증하지 못했습니다", err)
	}
	researchSnapshot, _ := json.Marshal(out.Research)
	if err = emit(Event{Stage: "research", Kind: "research_completed", Summary: "출처 발췌·해시와 주장별 참조를 보존했습니다", Payload: researchSnapshot}); err != nil {
		return finish("interrupted", "리서치 결과 보존에 실패했습니다", err)
	}
	out.Stage = "design"
	if err = emit(Event{Stage: "design", Kind: "started", Summary: "리서치 근거로 독립 공격 가설과 탐지 질문을 설계합니다"}); err != nil {
		return finish("interrupted", "시나리오 생성을 시작하지 못했습니다", err)
	}
	out.Design, err = deps.Design(ctx, req, out.Research)
	if err != nil {
		return finish("failed", "공격 가설·탐지 시나리오 생성을 완료하지 못했습니다", err)
	}
	if err = ValidateDesign(out.Design, out.Research); err != nil {
		return finish("failed", "시나리오의 단계·필수 필드·출처를 검증하지 못했습니다", err)
	}
	designSnapshot, _ := json.Marshal(out.Design)
	if err = emit(Event{Stage: "design", Kind: "design_completed", Summary: "출처와 연결된 가정 단계·탐지 질문을 보존했습니다", Payload: designSnapshot}); err != nil {
		return finish("interrupted", "시나리오 결과 보존에 실패했습니다", err)
	}
	out.Stage = "investigation"
	if err = emit(Event{Stage: "investigation", Kind: "started", Summary: "허용된 Splunk 로그에서 단계별 읽기 전용 자율 조사를 시작합니다"}); err != nil {
		return finish("interrupted", "로그 조사를 시작하지 못했습니다", err)
	}
	out.Investigation, err = deps.Investigate(ctx, req, out.Design, emit)
	if err != nil {
		// A late model/source failure must not erase already collected evidence.
		// Verification does not perform I/O and never upgrades a failed run into
		// a successful one, including when its individual records are observable.
		investigationErr := err
		out.Verification, err = Verify(req, out.Design, out.Investigation)
		status := "failed"
		switch out.Investigation.Status {
		case "budget_exhausted", "cancelled", "model_error", "interrupted":
			status = out.Investigation.Status
		}
		if err != nil {
			out.Verification.Status = "insufficient_data"
			out.Verification.Warnings = append(out.Verification.Warnings, "중단 전에 보존한 근거의 무결성·개수·크기를 검증하지 못했습니다. 실행 오류와 구분해 원본을 검토하세요.")
			return finish(status, "로그 조사 중단과 보존 근거의 검증 문제가 있습니다", errors.Join(investigationErr, err))
		}
		out.Verification.Warnings = append(out.Verification.Warnings, "조사가 완료되지 않았습니다. 확인된 개별 활동이 있어도 남은 단계·수집 공백을 해결한 전체 조사 결과는 아닙니다.")
		if ctx.Err() == nil {
			partialSnapshot, _ := json.Marshal(out.Verification)
			if saveErr := emit(Event{Stage: "verification", Kind: "partial_verification", Summary: "중단 전에 확보한 원본 근거만 검증했습니다. 실행 실패 상태는 유지합니다", Payload: partialSnapshot}); saveErr != nil {
				return finish(status, "중단 전 근거 판정 보존에 실패했습니다", saveErr)
			}
		}
		return finish(status, "로그 조사를 완료하지 못했습니다. 이미 수집한 근거와 개별 판정은 보존합니다", investigationErr)
	}
	out.Stage = "verification"
	if err = emit(Event{Stage: "verification", Kind: "started", Summary: "원본 참조·조사 범위·필수 필드와 단계별 관측을 검증합니다"}); err != nil {
		return finish("interrupted", "근거 검증을 시작하지 못했습니다", err)
	}
	out.Verification, err = Verify(req, out.Design, out.Investigation)
	if err != nil {
		return finish("failed", "수집 근거를 검증하지 못했습니다", err)
	}
	status := "completed"
	if out.Verification.Status == "insufficient_data" {
		status = "insufficient_data"
	}
	switch out.Investigation.Status {
	case "budget_exhausted", "cancelled", "model_error", "interrupted", "failed":
		status = out.Investigation.Status
	}
	return finish(status, "", nil)
}
