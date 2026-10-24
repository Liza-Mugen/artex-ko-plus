package hunting

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

const impactLimitation = "원본 참조와 필드 존재는 AI 해석의 의미나 코드 실행·계정 탈취·침해 성공을 독립적으로 증명하지 않습니다. 영향은 별도 원본 증거와 검증이 필요합니다."

func unique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range in {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func scopeWithin(outer, inner investigation.Scope) bool {
	return strings.EqualFold(outer.Target, inner.Target) && !inner.Start.Before(outer.Start) && !inner.End.After(outer.End) && inner.End.After(inner.Start) && (outer.PathPrefix == "" || investigation.MatchPath(inner.PathPrefix, outer.PathPrefix))
}

func eventWithin(event investigation.Event, scope investigation.Scope, targetConfirmed bool) bool {
	if event.Timestamp.Before(scope.Start) || !event.Timestamp.Before(scope.End) || (event.Target == "" && !targetConfirmed) || (event.Target != "" && !investigation.MatchTarget(event.Target, scope.Target)) {
		return false
	}
	return scope.PathPrefix == "" || investigation.MatchPath(event.Path, scope.PathPrefix)
}

func rawLookup(fields map[string]any, path string) (any, bool) {
	if value, ok := fields[path]; ok {
		return value, true
	}
	var value any = fields
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return value, true
}

func scalarPresent(value any) bool {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case json.Number, float64, bool:
		return true
	case []any:
		return len(v) == 1 && scalarPresent(v[0])
	default:
		return false
	}
}

func fieldPresent(event investigation.Event, mapping investigation.Mapping, name string) bool {
	// Canonical values have already been normalized by the collection parser.
	fields := []struct {
		canonical string
		mapped    string
		present   bool
	}{
		{"timestamp", mapping.Timestamp, !event.Timestamp.IsZero()},
		{"event_id", mapping.EventID, event.ID != ""},
		{"target", mapping.Target, event.Target != ""},
		{"path", mapping.Path, event.Path != ""},
		{"source_ip", mapping.SourceIP, event.SourceIP != ""},
		{"user", mapping.User, event.User != ""},
		{"session", mapping.Session, event.Session != ""},
		{"action", mapping.Action, event.Action != ""},
		{"status", mapping.Status, event.Status != ""},
		{"bytes", mapping.Bytes, event.Bytes != nil},
		{"verification_id", mapping.VerificationID, event.VerificationID != ""},
		{"event_kind", mapping.EventKind, event.EventKind != ""},
		{"response_complete", mapping.ResponseComplete, event.ResponseComplete != nil},
	}
	for _, field := range fields {
		if name == field.canonical || field.mapped != "" && name == field.mapped {
			return field.present
		}
	}
	var raw map[string]any
	if json.Unmarshal([]byte(event.Raw), &raw) != nil {
		return false
	}
	if value, ok := rawLookup(raw, name); ok {
		return scalarPresent(value)
	}
	if original, ok := raw["_raw"].(string); ok {
		var fallback map[string]any
		if json.Unmarshal([]byte(original), &fallback) == nil {
			value, ok := rawLookup(fallback, name)
			return ok && scalarPresent(value)
		}
	}
	return false
}

func stageMatches(stage Stage, event investigation.Event) bool {
	if len(stage.EventKinds) > 0 {
		match := false
		for _, kind := range stage.EventKinds {
			match = match || strings.EqualFold(kind, event.EventKind)
		}
		if !match {
			return false
		}
	}
	if len(stage.PathContains) > 0 {
		match := false
		for _, path := range stage.PathContains {
			match = match || strings.Contains(event.Path, path)
		}
		if !match {
			return false
		}
	}
	return true
}

// Verify checks actual retained events, bounds and field availability, not just
// the model's status. evidence_observed means an AI observation has in-scope
// evidence with required fields; it never means an exploit or impact is proven.
func Verify(req Request, design Design, in InvestigationResult) (Verification, error) {
	out := Verification{Status: "insufficient_data", Stages: []StageAssessment{}, Warnings: []string{impactLimitation}}
	var err error
	if req, err = NormalizeRequest(req); err != nil {
		return out, err
	}
	// A direct verifier invocation must also check the bounded stage structure.
	provenance := Research{}
	seenSources := map[string]bool{}
	for _, stage := range design.Stages {
		for _, source := range stage.SourceIDs {
			if !seenSources[source] {
				provenance.Sources = append(provenance.Sources, ResearchSource{ID: source})
				seenSources[source] = true
			}
		}
	}
	if err = ValidateDesign(design, provenance); err != nil {
		return out, err
	}
	if len(in.Collections) > MaxCollections || len(in.Observations) > 256 || len(in.Gaps) > 64 || len(in.NextSteps) > 64 || in.Usage.Rounds < 0 || in.Usage.ModelCalls < 0 || in.Usage.Queries < 0 || in.Usage.RemoteQueries < 0 || in.Usage.InputTokens < 0 || in.Usage.OutputTokens < 0 {
		return out, fmt.Errorf("%w: 조사 결과 개수 또는 사용량 한도를 확인해 주세요", ErrInvalid)
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > MaxEvidenceBytes {
		return out, fmt.Errorf("%w: 조사 근거 보존 크기를 초과했습니다", ErrBudget)
	}
	events := map[string]investigation.Event{}
	mappings := map[string]investigation.Mapping{}
	complete := len(in.Collections) > 0 && in.ScopeCoverageConfirmed
	fullScopeCollection := false
	integrityIssue := false
	count := 0
	for _, collection := range in.Collections {
		count += len(collection.Events)
		if len(collection.Events) > investigation.MaxEvents || count > MaxEvidenceEvents {
			return out, fmt.Errorf("%w: 조사 이벤트 개수 한도를 초과했습니다", ErrBudget)
		}
		if collection.SourceKind != "splunk" || !scopeWithin(req.Scope, collection.Scope) || collection.CollectedAt.IsZero() || collection.CollectedAt.After(time.Now().Add(5*time.Minute)) {
			integrityIssue = true
			out.Warnings = append(out.Warnings, "Splunk 출처·원래 대상·기간·경로 또는 수집 시각과 맞지 않는 근거 묶음을 제외했습니다.")
			continue
		}
		// Splunk uses _time even when another initial timestamp was selected.
		expectedMapping := req.Mapping
		if collection.SourceKind == "splunk" {
			expectedMapping.Timestamp = "_time"
		}
		if collection.Mapping != expectedMapping {
			integrityIssue = true
			out.Warnings = append(out.Warnings, "허용한 원본 필드 매핑과 다른 근거 묶음을 제외했습니다.")
			continue
		}
		if collection.Scope == req.Scope && collection.Complete && collection.CoverageConfirmed {
			fullScopeCollection = true
		}
		if !collection.Complete || !collection.CoverageConfirmed || collection.Stats.InvalidEvents > 0 || collection.Stats.Truncated > 0 {
			complete = false
		}
		out.Warnings = append(out.Warnings, collection.Warnings...)
		for _, event := range collection.Events {
			if event.Ref == "" || strings.TrimSpace(event.Raw) == "" || len(event.Raw) > investigation.MaxRecordBytes || !eventWithin(event, collection.Scope, collection.TargetScopeConfirmed) || !eventWithin(event, req.Scope, collection.TargetScopeConfirmed) {
				integrityIssue = true
				out.Warnings = append(out.Warnings, "원문 또는 원래 조사 범위가 확인되지 않은 이벤트를 제외했습니다.")
				continue
			}
			if old, ok := events[event.Ref]; ok && !reflect.DeepEqual(old, event) {
				integrityIssue = true
				out.Warnings = append(out.Warnings, "같은 근거 참조의 원문 또는 정규화 값이 달라 해당 실행의 확정적 판정을 보류했습니다.")
				continue
			}
			events[event.Ref], mappings[event.Ref] = event, collection.Mapping
		}
	}
	complete = complete && fullScopeCollection && !integrityIssue
	byStage := map[string][]Observation{}
	stageIDs := map[string]bool{}
	for _, stage := range design.Stages {
		stageIDs[stage.ID] = true
	}
	for _, observation := range in.Observations {
		if !stageIDs[observation.StageID] {
			integrityIssue = true
			out.Warnings = append(out.Warnings, "없는 단계로 연결된 AI 관측을 제외했습니다.")
			continue
		}
		byStage[observation.StageID] = append(byStage[observation.StageID], observation)
	}
	for _, stage := range design.Stages {
		a := StageAssessment{StageID: stage.ID, Status: "insufficient_data", EvidenceRefs: []string{}, KnownVerificationRefs: []string{}, MissingFields: []string{}, Reasons: []string{}, Alternatives: append([]string{}, stage.BenignAlternatives...), NextSteps: []string{}}
		observed, inferred := false, false
		observationKeys := map[string]bool{}
		for _, observation := range byStage[stage.ID] {
			key, _ := json.Marshal(observation)
			if observationKeys[string(key)] {
				continue
			}
			observationKeys[string(key)] = true
			bad := !textValid(observation.Summary, 1, 4000) || !listValid(observation.EvidenceRefs, 10, 512) || !listValid(observation.Alternatives, 8, 1000) || !listValid(observation.NextSteps, 8, 1000)
			if observation.Kind != "observed" && observation.Kind != "inferred" && observation.Kind != "insufficient_data" || observation.Kind == "inferred" && len(observation.Alternatives) == 0 || observation.Kind != "insufficient_data" && len(observation.EvidenceRefs) == 0 {
				bad = true
			}
			missing, accepted := []string{}, []string{}
			for _, ref := range observation.EvidenceRefs {
				event, ok := events[ref]
				if !ok {
					bad = true
					a.Reasons = append(a.Reasons, "AI 관측이 수집하지 않았거나 범위 밖인 원본 참조를 인용했습니다.")
					continue
				}
				if event.KnownARTEX {
					a.KnownVerificationRefs = append(a.KnownVerificationRefs, ref)
					continue
				}
				if !stageMatches(stage, event) {
					bad = true
					a.Reasons = append(a.Reasons, "인용 이벤트가 이 단계의 명시적 이벤트 종류·경로 조건과 다릅니다.")
					continue
				}
				for _, field := range stage.RequiredFields {
					if !fieldPresent(event, mappings[ref], field) {
						missing = append(missing, field)
					}
				}
				accepted = append(accepted, ref)
			}
			a.MissingFields = append(a.MissingFields, missing...)
			a.Alternatives = append(a.Alternatives, observation.Alternatives...)
			a.NextSteps = append(a.NextSteps, observation.NextSteps...)
			if bad {
				a.RejectedObservations++
				continue
			}
			a.EvidenceRefs = append(a.EvidenceRefs, accepted...)
			if len(missing) > 0 || len(accepted) == 0 {
				continue
			}
			observed = observed || observation.Kind == "observed"
			inferred = inferred || observation.Kind == "inferred"
		}
		// Availability is checked even when the model never cites a record.
		candidates, available := 0, map[string]bool{}
		for ref, event := range events {
			if event.KnownARTEX {
				continue
			}
			for _, field := range stage.RequiredFields {
				available[field] = available[field] || fieldPresent(event, mappings[ref], field)
			}
			if stageMatches(stage, event) {
				candidates++
			}
		}
		for _, field := range stage.RequiredFields {
			if !available[field] {
				a.MissingFields = append(a.MissingFields, field)
			}
		}
		switch {
		case integrityIssue || a.RejectedObservations > 0:
			a.Reasons = append(a.Reasons, "원본 참조·범위 또는 AI 관측의 무결성 문제를 해결해야 합니다.")
		case len(a.MissingFields) > 0:
			a.Reasons = append(a.Reasons, "인용 근거 또는 수집된 로그에 이 단계의 필수 필드가 없습니다.")
		case observed:
			a.Status = "evidence_observed"
			a.Summary = "범위 안의 원본 참조와 필수 필드를 갖춘 활동 관측이 있습니다. 공격 성공이나 영향 확정은 아닙니다."
		case inferred:
			a.Status = "inferred"
			a.Summary = "실제 근거를 연결한 AI 가설이 있습니다. 정상 대안과 추가 검증이 필요합니다."
		case complete && len(events) > 0 && candidates == 0 && (len(stage.EventKinds) > 0 || len(stage.PathContains) > 0):
			a.Status = "not_observed"
			a.Summary = "완료된 조회 범위에서 이 단계의 명시적 이벤트·경로 조건을 관측하지 못했습니다. 침해 부재를 뜻하지 않습니다."
		default:
			a.Reasons = append(a.Reasons, "확인한 관측 또는 충분한 수집 범위가 없어 해당 질문의 결론을 내릴 수 없습니다.")
		}
		if !complete {
			a.Reasons = append(a.Reasons, "수집 범위·한도 또는 파싱 공백이 있어 미관측을 확정할 수 없습니다.")
		}
		if len(a.KnownVerificationRefs) > 0 {
			a.Reasons = append(a.Reasons, "등록된 ARTEX 검증 이벤트는 외부 침해 근거에서 구분했습니다.")
		}
		if a.Summary == "" {
			a.Summary = "자료 부족 또는 원본 검증 문제로 이 단계는 판단할 수 없습니다."
		}
		a.EvidenceRefs, a.KnownVerificationRefs, a.MissingFields = unique(a.EvidenceRefs), unique(a.KnownVerificationRefs), unique(a.MissingFields)
		sort.Strings(a.MissingFields)
		a.Reasons, a.Alternatives, a.NextSteps = unique(a.Reasons), unique(a.Alternatives), unique(a.NextSteps)
		out.Stages = append(out.Stages, a)
	}
	states := map[string]string{}
	for _, assessment := range out.Stages {
		states[assessment.StageID] = assessment.Status
	}
	insufficient := in.Status == "insufficient_data"
	for i, stage := range design.Stages {
		insufficient = insufficient || out.Stages[i].Status == "insufficient_data"
		for _, dependency := range stage.DependsOn {
			if states[dependency] != "evidence_observed" {
				out.Stages[i].Reasons = append(out.Stages[i].Reasons, "선행 단계 "+dependency+"의 활동 근거가 확인되지 않아 공격 연쇄가 입증된 것은 아닙니다.")
			}
		}
	}
	if !insufficient {
		out.Status = "completed"
	}
	out.Summary = "단계별 원본 참조·조사 범위·필수 필드를 검토했습니다. 개별 활동 관측과 추론을 구분하며 침해 또는 코드 실행 성공을 확정하지 않습니다."
	out.Warnings = unique(append(out.Warnings, in.Gaps...))
	return out, nil
}
