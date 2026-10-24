package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/hunting"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
)

func huntStageOrder(stages []hunting.Stage) []hunting.Stage {
	byID := map[string]hunting.Stage{}
	for _, s := range stages {
		byID[s.ID] = s
	}
	seen := map[string]bool{}
	out := []hunting.Stage{}
	var visit func(string)
	visit = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		s := byID[id]
		for _, dep := range s.DependsOn {
			visit(dep)
		}
		out = append(out, s)
	}
	for _, s := range stages {
		visit(s.ID)
	}
	return out
}

// The reused Investigator passes Question through a 2000-byte UTF-8 clip in
// both planner and worker sessions. Build a complete JSON contract inside that
// boundary instead of letting the clip cut a serialized stage halfway through.
const (
	huntStageContextBytes   = 2000
	huntStageTimeoutSeconds = 420 // bounded headroom for slower reasoning models
)

type huntPriorContext struct {
	StageID string `json:"stage_id"`
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
}

type huntStageContext struct {
	StageID            string            `json:"stage_id"`
	DetectionQuestion  string            `json:"detection_question"`
	RequiredFields     []string          `json:"required_fields"`
	SuccessCriteria    string            `json:"success_criteria"`
	BenignAlternatives []string          `json:"benign_alternatives"`
	Prior              *huntPriorContext `json:"prior,omitempty"`
	Truncated          bool              `json:"truncated"`
	Notice             string            `json:"notice"`
}

func huntStageQuestion(stage hunting.Stage, prior []hunting.Observation) (string, bool, error) {
	if strings.TrimSpace(stage.DetectionQuestion) == "" || strings.TrimSpace(stage.SuccessCriteria) == "" || len(stage.RequiredFields) == 0 || len(stage.BenignAlternatives) == 0 {
		return "", false, fmt.Errorf("%w: 단계 조사 계약에 질문·필드·판정 기준·정상 대안이 필요합니다", hunting.ErrInvalid)
	}
	view := huntStageContext{
		StageID: stage.ID, DetectionQuestion: stage.DetectionQuestion,
		RequiredFields:  append([]string{}, stage.RequiredFields...),
		SuccessCriteria: stage.SuccessCriteria, BenignAlternatives: append([]string{}, stage.BenignAlternatives...),
		Notice: "이 단계만 조사. 필수 필드를 확인하고 read_evidence로 원문을 읽은 뒤 관측을 기록하세요.",
	}
	if len(prior) > 0 {
		last := prior[len(prior)-1]
		view.Prior = &huntPriorContext{last.StageID, last.Kind, huntTextBytes(last.Summary, 100)}
		view.Truncated = len(prior) > 1 || view.Prior.Summary != last.Summary
	}
	for {
		if view.Truncated {
			view.Notice = "일부 축약. 잘린 조건은 미확인으로 남기고 관측 전 read_evidence로 원문을 확인하세요."
		}
		encoded, err := json.Marshal(view)
		if err != nil {
			return "", view.Truncated, err
		}
		if len(encoded) <= huntStageContextBytes {
			return string(encoded), view.Truncated, nil
		}
		view.Truncated = true
		// Current-stage requirements take precedence over earlier AI summaries.
		if view.Prior != nil {
			view.Prior = nil
			continue
		}
		if len(view.BenignAlternatives) > 1 {
			view.BenignAlternatives = view.BenignAlternatives[:len(view.BenignAlternatives)-1]
			continue
		}
		// Keep every required field exact. Shorten semantic excerpts only, and
		// explicitly leave conditions beyond those excerpts unverified. Prefer
		// retaining the question over equally large secondary text.
		type candidate struct {
			text            *string
			minimum, weight int
		}
		candidates := []candidate{{&view.DetectionQuestion, 32, 2}, {&view.SuccessCriteria, 32, 1}, {&view.BenignAlternatives[0], 16, 1}}
		best, score := -1, 0
		for i, item := range candidates {
			available := len(*item.text) - item.minimum
			if available > 0 && (best < 0 || available/item.weight > score) {
				best, score = i, available/item.weight
			}
		}
		if best < 0 {
			return "", true, fmt.Errorf("%w: 필수 필드와 최소 조사 조건이 2000바이트 계약에 들어가지 않습니다. 단계를 나누어야 합니다", hunting.ErrInvalid)
		}
		item := candidates[best]
		limit := max(item.minimum, len(*item.text)-max(16, (len(*item.text)-item.minimum)/4))
		shortened := huntTextBytes(*item.text, limit)
		if shortened == "" || shortened == *item.text {
			return "", true, fmt.Errorf("%w: 조사 조건을 손실 없이 전달할 수 없습니다", hunting.ErrInvalid)
		}
		*item.text = shortened
	}
}

func huntStageSummary(question string) string {
	runes := []rune(question)
	if len(runes) > 900 {
		return string(runes[:900]) + "…"
	}
	return question
}

func (s *Server) investigateHunt(ctx context.Context, id int64, in hunting.Request, design hunting.Design, provider *huntProvider, cfg agent.Config, emit func(hunting.Event) error) (hunting.InvestigationResult, error) {
	out := hunting.InvestigationResult{Status: "completed", Summary: "단계별 로그 조사를 진행했습니다. 조사 상태와 근거 판정을 확인하세요", Collections: []investigation.Collection{}, Observations: []hunting.Observation{}}
	queryCache := map[string]investigation.Collection{}
	remoteCalls := int64(0)
	var searchMu sync.Mutex
	// One read-only adapter is shared by bootstrap and all planner/worker stages.
	search := func(queryCtx context.Context, q agent.InvestigationSearch) (investigation.Collection, error) {
		// Worker tools may arrive concurrently. Serialize admission, cache and
		// collection writes so duplicate/in-flight work shares the same budget.
		searchMu.Lock()
		defer searchMu.Unlock()
		var empty investigation.Collection
		if err := queryCtx.Err(); err != nil {
			return empty, err
		}
		if err := agent.ValidateInvestigationSearch(in.Scope, q); err != nil {
			return empty, err
		}
		if err := validateInvestigationPivot(in.Scope, q); err != nil {
			return empty, err
		}
		active, err := s.m.pg.GetHunt(queryCtx, id)
		if err != nil {
			return empty, err
		}
		if active.Status != "running" {
			return empty, db.ErrHuntInactive
		}
		current, err := s.huntSource(queryCtx, in)
		if err != nil {
			return empty, err
		}
		keyBytes, _ := json.Marshal(q)
		key := string(keyBytes)
		if cached, ok := queryCache[key]; ok {
			return cached, nil
		}
		if remoteCalls >= 6 {
			return empty, agent.ErrInvestigationBudget
		}
		remoteCalls++
		out.Usage.RemoteQueries = remoteCalls
		auth, err := s.securitySourceCredentials(current)
		if err != nil {
			return empty, err
		}
		runs, err := s.m.pg.KnownDefensiveVerifications(queryCtx, in.Scope)
		if err != nil {
			return empty, err
		}
		ids := []string{}
		for _, run := range runs {
			ids = append(ids, run.ID)
		}
		collection, err := securitysource.FetchInvestigationFiltered(queryCtx, current.Config, auth, q.Scope, in.Mapping, in.Sourcetypes, ids, securitysource.InvestigationFilters{SourceIP: q.SourceIP, User: q.User, Session: q.Session, EventKind: q.EventKind, PathContains: q.PathContains})
		if err != nil {
			return empty, err
		}
		boundDefensiveCaseMarkers(&collection, runs)
		collection.TargetScopeConfirmed = true
		// Successful export alone cannot establish sensor coverage.
		collection.CoverageConfirmed = false
		proof, _ := json.Marshal(investigationQueryProof{q, collection})
		if err = emit(hunting.Event{Stage: "hunting", Kind: "evidence_collection", Summary: fmt.Sprintf("허용 범위에서 원문 %d건 수집", len(collection.Events)), Payload: proof}); err != nil {
			return empty, err
		}
		queryCache[key] = collection
		out.Collections = append(out.Collections, collection)
		return collection, nil
	}
	initial, err := search(ctx, agent.InvestigationSearch{Scope: in.Scope, Remote: true})
	if err != nil {
		out.Status = "insufficient_data"
		out.Gaps = append(out.Gaps, "초기 Splunk 근거를 수집하지 못했습니다")
		return out, err
	}
	queries := int64(1) // the bootstrap is part of the same campaign budget
	out.Usage.Queries = queries
	for _, stage := range huntStageOrder(design.Stages) {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		blocked := false
		if len(stage.DependsOn) > 0 {
			assessment, verifyErr := hunting.Verify(in, design, out)
			if verifyErr != nil {
				return out, verifyErr
			}
			states := map[string]string{}
			for _, a := range assessment.Stages {
				states[a.StageID] = a.Status
			}
			for _, dep := range stage.DependsOn {
				if states[dep] != "evidence_observed" {
					blocked = true
				}
			}
		}
		if blocked {
			out.Observations = append(out.Observations, hunting.Observation{StageID: stage.ID, Kind: "insufficient_data", Summary: "선행 단계의 직접 근거가 부족하여 후속 가설 조사를 보류했습니다", NextSteps: []string{"선행 단계의 로그·필드·정상 대안을 확인하세요"}})
			continue
		}
		calls, _, _ := provider.snapshot()
		if calls >= huntProviderMaxCalls || queries >= 12 {
			out.Status = "budget_exhausted"
			out.Gaps = append(out.Gaps, "단계 전체 누적 조사 한도에 도달했습니다")
			break
		}
		question, shortened, contextErr := huntStageQuestion(stage, out.Observations)
		if contextErr != nil {
			out.Observations = append(out.Observations, hunting.Observation{StageID: stage.ID, Kind: "insufficient_data", Summary: "필수 필드와 최소 조사 조건을 실행 문맥 한도 안에 전달할 수 없어 이 단계를 보류했습니다", NextSteps: []string{"저장된 원래 설계를 검토하고 단계를 더 작은 질문으로 나누세요"}})
			out.Gaps = huntUnique(append(out.Gaps, stage.ID+": 조사 문맥 전달 한도. 원래 설계는 보존했으며 필수 필드를 삭제하지 않았습니다."), 32)
			continue
		}
		if shortened {
			out.Gaps = huntUnique(append(out.Gaps, stage.ID+": 모델 조사 문맥의 일부 텍스트·이전 관측을 축약했습니다. 원래 설계는 보존하며 잘린 조건은 미확인입니다."), 32)
		}
		if err := emit(hunting.Event{Stage: "hunting", Kind: "stage_started", Summary: huntStageSummary(stage.DetectionQuestion), Detail: stage.ID}); err != nil {
			return out, err
		}
		if err := emit(hunting.Event{Stage: "hunting", Kind: "stage_context", Summary: "필수 필드를 보존한 실행 조사 계약을 기록했습니다", Detail: stage.ID, Payload: json.RawMessage(question)}); err != nil {
			return out, err
		}
		var progressErr error
		opts := agent.InvestigatorOptions{Provider: provider, NonStreaming: !cfg.Stream, MaxTokens: 2048, SessionID: fmt.Sprintf("hunt-%d-%s", id, stage.ID), Title: design.Title, Question: question, Collection: huntSeed(initial, out.Collections), Search: search, Budget: agent.InvestigatorBudget{MaxRounds: 3, MaxModelCalls: int(huntProviderMaxCalls - calls), MaxQueries: int(12 - queries), MaxTokens: 512 << 10, TimeoutSeconds: huntStageTimeoutSeconds}}
		opts.Emit = func(p agent.InvestigatorProgress) {
			if progressErr != nil || p.Kind == "thinking" || p.Kind == "token" {
				return
			}
			raw, _ := json.Marshal(p)
			summary := strings.TrimSpace(p.Summary)
			if summary == "" {
				summary = "조사 진행: " + p.Kind
			}
			if runes := []rune(summary); len(runes) > 900 {
				summary = string(runes[:900]) + "…"
			}
			progressErr = emit(hunting.Event{Stage: "hunting", Kind: "investigator_" + p.Kind, Summary: summary, Detail: stage.ID, Payload: raw})
		}
		report, runErr := agent.RunInvestigation(ctx, opts)
		queries += int64(report.Usage.Queries)
		out.Usage.Queries = queries
		out.Usage.Rounds += int64(len(report.Decisions))
		out.Gaps = append(out.Gaps, report.Gaps...)
		out.NextSteps = append(out.NextSteps, report.NextSteps...)
		out.Gaps = huntUnique(out.Gaps, 32)
		out.NextSteps = huntUnique(out.NextSteps, 32)
		for _, o := range report.Observations {
			out.Observations = append(out.Observations, hunting.Observation{StageID: stage.ID, Kind: o.Kind, Summary: o.Summary, EvidenceRefs: o.EvidenceRefs, Alternatives: o.Alternatives, NextSteps: o.NextSteps})
		}
		if len(report.Observations) == 0 {
			out.Observations = append(out.Observations, hunting.Observation{StageID: stage.ID, Kind: "insufficient_data", Summary: report.Summary})
		}
		if progressErr != nil {
			return out, progressErr
		}
		// One stage can exhaust its own bounded planning rounds while leaving
		// independent detection questions unexamined. Preserve the partial
		// observations, mark that stage unresolved, and continue while the
		// campaign's shared model budget still permits it. Runtime/provider
		// errors and the campaign-wide cap remain terminal.
		if report.Status == "budget_exhausted" && runErr == nil && !provider.exhausted() {
			used, _, _ := provider.snapshot()
			if used < huntProviderMaxCalls {
				out.Status = "insufficient_data"
				out.Observations = append(out.Observations, hunting.Observation{StageID: stage.ID, Kind: "insufficient_data", Summary: "이 단계의 조사 회차 또는 시간 한도에 도달하여 결론을 보류했습니다", NextSteps: []string{"저장된 근거와 미확인 필드를 검토한 뒤 해당 단계를 다시 조사하세요"}})
				out.Gaps = huntUnique(append(out.Gaps, stage.ID+": 단계별 조사 한도에 도달해 남은 조건은 미확인입니다."), 32)
				continue
			}
		}
		if report.Status != "completed" {
			out.Status = report.Status
		}
		if runErr != nil {
			if errors.Is(runErr, agent.ErrInvestigationBudget) {
				out.Status = "budget_exhausted"
			}
			return out, runErr
		}
		if report.Status == "budget_exhausted" || report.Status == "cancelled" || report.Status == "model_error" {
			break
		}
	}
	out.Gaps = huntUnique(out.Gaps, 32)
	out.NextSteps = huntUnique(out.NextSteps, 32)
	out.Usage.ModelCalls, out.Usage.InputTokens, out.Usage.OutputTokens = provider.snapshot()
	return out, nil
}

// Later stages can inspect earlier query results without repeating a remote
// request. Receipts remain separate in Collections, preserving their scopes.
func huntSeed(initial investigation.Collection, collections []investigation.Collection) investigation.Collection {
	out := initial
	out.Events = append([]investigation.Event{}, initial.Events...)
	seen := map[string]bool{}
	for _, e := range out.Events {
		seen[e.Ref] = true
	}
	for _, c := range collections {
		for _, e := range c.Events {
			if seen[e.Ref] {
				continue
			}
			if len(out.Events) >= investigation.MaxEvents {
				out.Complete = false
				return out
			}
			out.Events = append(out.Events, e)
			seen[e.Ref] = true
		}
	}
	return out
}
func huntUnique(in []string, limit int) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}
