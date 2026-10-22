package securitysource

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/investigation"
)

const ClosedLoopRuleEngine = "splunk-shadow-exact-contains-v1"
const maxClosedLoopSearchBytes = 64 << 10
const baselineShadowField = "_aegis_shadow_baseline"
const candidateShadowField = "_aegis_shadow_candidate"

// ClosedLoopRuleEvent reports an ad hoc rule evaluation, never an emitted alert.
// Raw retains the exact returned native result object, including original _raw.
type ClosedLoopRuleEvent struct {
	EventID    string          `json:"event_id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Baseline   string          `json:"baseline"`
	Candidate  string          `json:"candidate"`
	Raw        json.RawMessage `json:"raw"`
}

type ClosedLoopSearchResult struct {
	Engine              string                       `json:"engine"`
	Scope               string                       `json:"scope"`
	Query               string                       `json:"query"`
	BaselineRuleSHA256  string                       `json:"baseline_rule_sha256"`
	CandidateRuleSHA256 string                       `json:"candidate_rule_sha256"`
	CorrelationID       string                       `json:"correlation_id"`
	WindowStart         time.Time                    `json:"window_start"`
	WindowEnd           time.Time                    `json:"window_end"`
	QueryStartedAt      time.Time                    `json:"query_started_at"`
	QueryFinishedAt     time.Time                    `json:"query_finished_at"`
	CollectedAt         time.Time                    `json:"collected_at"`
	Complete            bool                         `json:"complete"`
	Truncated           int                          `json:"truncated"`
	TotalRows           int                          `json:"total_rows"`
	Warnings            []string                     `json:"warnings"`
	ErrorCode           string                       `json:"error_code,omitempty"`
	HTTPStatus          int                          `json:"http_status,omitempty"`
	Events              []ClosedLoopRuleEvent        `json:"events"`
	Files               []investigation.FileEvidence `json:"files"`
	Upload              *UploadProvenance            `json:"upload,omitempty"`
}

// ClosedLoopRuleFields is a behavioral-field allowlist. Execution IDs, labels,
// sensor identities and observation timestamps cannot become rule conditions.
// It is also the contract used by proposal generation and managed lab deployment.
func ClosedLoopRuleFields(mapping investigation.Mapping) []string {
	set := map[string]bool{}
	for _, f := range []string{mapping.Target, mapping.Path, mapping.SourceIP, mapping.User,
		mapping.Session, mapping.Action, mapping.Status, mapping.Bytes, mapping.EventKind,
		mapping.ResponseComplete, "method", "rule_id", "matched_rules", "message",
		"transaction_complete", "request_target", "query_string"} {
		if f != "" && fieldName.MatchString(f) && !closedLoopReservedField(f, mapping) {
			set[f] = true
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func closedLoopReservedField(f string, m investigation.Mapping) bool {
	fold := strings.ToLower(f)
	if strings.HasPrefix(fold, "_aegis_") {
		return true
	}
	for _, reserved := range []string{m.EventID, m.VerificationID, m.Timestamp, "id", "event_id",
		"label", "ground_truth", "artex_verification_id", "correlation_id", "request_uid",
		"audit_event_id", "alert_id", "_raw", "_time", "timestamp", "event_epoch",
		"occurred_at", "baseline_alert_at", "candidate_alert_at", "alert_created_at",
		"source", "host", "index", "sourcetype", "_cd", "_bkt", "splunk_server",
		"rule_sha256", "detection_rule_id", "detection_engine"} {
		if reserved != "" && strings.EqualFold(f, reserved) {
			return true
		}
	}
	return false
}

func validateClosedLoopRules(mapping investigation.Mapping, rules ...closedloop.Rule) error {
	allowed := map[string]bool{}
	for _, f := range ClosedLoopRuleFields(mapping) {
		allowed[f] = true
	}
	for _, rule := range rules {
		if err := closedloop.ValidateRule(rule); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if !utf8.ValidString(rule.Name) || strings.ContainsAny(rule.Name, "\x00\r\n") {
			return fmt.Errorf("%w: 규칙 이름을 확인하세요", ErrInvalid)
		}
		for _, branch := range rule.Any {
			for _, cond := range branch.All {
				if !allowed[cond.Field] || !utf8.ValidString(cond.Value) || strings.ContainsAny(cond.Value, "\x00\r\n") {
					return fmt.Errorf("%w: 규칙은 허용된 행동 필드와 UTF-8 리터럴 값만 사용할 수 있습니다", ErrInvalid)
				}
			}
		}
	}
	return nil
}

func validateClosedLoopScope(c Config, q Query, scope investigation.Scope, mapping investigation.Mapping) error {
	if !correlationName.MatchString(q.CorrelationID) || q.Start.IsZero() || !q.End.After(q.Start) ||
		q.End.Sub(q.Start) > 24*time.Hour || !q.Start.Equal(scope.Start) || !q.End.Equal(scope.End) {
		return fmt.Errorf("%w: 같은 실행 UUID와 최대 24시간의 동일 조회 구간이 필요합니다", ErrInvalid)
	}
	if mapping.VerificationID != c.CorrelationField || mapping.Target == "" || mapping.Path == "" || scope.PathPrefix == "" {
		return fmt.Errorf("%w: 실행 UUID·대상·경로 범위의 원본 필드 매핑이 필요합니다", ErrInvalid)
	}
	if err := investigation.ValidateScope(scope, time.Now().UTC()); err != nil {
		return err
	}
	return investigation.ValidateMapping(mapping)
}

// BuildClosedLoopRuleSearch compiles structured rules into one bounded search.
// Both rules evaluate the same complete scoped audit input. Matching predicates
// never replace the mandatory index/source/target/path/correlation/time bounds.
func BuildClosedLoopRuleSearch(c Config, q Query, scope investigation.Scope, mapping investigation.Mapping, baseline, candidate closedloop.Rule) (string, error) {
	var err error
	c, err = Validate(c)
	if err != nil {
		return "", err
	}
	if err = validateClosedLoopScope(c, q, scope, mapping); err != nil {
		return "", err
	}
	if err = validateClosedLoopRules(mapping, baseline, candidate); err != nil {
		return "", err
	}
	auditStreams := make([]LogStream, 0, len(c.Streams))
	for _, stream := range c.Streams {
		if stream.Kind == "audit" {
			auditStreams = append(auditStreams, stream)
		}
	}
	search, err := buildInvestigationSearchForStreams(scope, mapping, auditStreams)
	if err != nil {
		return "", err
	}
	suffix := " | head " + strconv.Itoa(investigation.MaxRows+1)
	search = strings.TrimSuffix(search, suffix)
	search += " | where mvcount('" + c.CorrelationField + "') = 1 AND '" + c.CorrelationField + "' = " + investigationLiteral(q.CorrelationID)
	fields := []string{}
	for _, rule := range []closedloop.Rule{baseline, candidate} {
		for _, branch := range rule.Any {
			for _, cond := range branch.All {
				fields = append(fields, cond.Field)
				if flag := closedLoopTruncationField(cond.Field); flag != "" {
					fields = append(fields, flag)
				}
			}
		}
	}
	search += splunkDeduplicateFields(fields...)
	search += compileClosedLoopRule(baseline, "b", baselineShadowField)
	search += compileClosedLoopRule(candidate, "c", candidateShadowField)
	// Remove only compiler-owned intermediates; retain every native source field.
	search += " | fields - _aegis_shadow_b_cond_* _aegis_shadow_b_branch_* _aegis_shadow_c_cond_* _aegis_shadow_c_branch_*" + suffix
	if len(search) > maxClosedLoopSearchBytes {
		return "", fmt.Errorf("%w: 생성된 검색식은 64 KiB 이하여야 합니다. 규칙을 줄여 주세요", ErrInvalid)
	}
	return search, nil
}

func compileClosedLoopRule(rule closedloop.Rule, kind, output string) string {
	var conditions, branches []string
	var hits, unknowns []string
	for i, branch := range rule.Any {
		var falseTerms, unknownTerms []string
		for j, cond := range branch.All {
			name := fmt.Sprintf("_aegis_shadow_%s_cond_%d_%d", kind, i, j)
			value, expected := "tostring('"+cond.Field+"')", cond.Value
			if !cond.CaseSensitive {
				value = "lower(" + value + ")"
				expected = strings.ToLower(expected)
			}
			predicate := value + " = " + investigationLiteral(expected)
			if cond.Op == "contains" {
				predicate = "match(" + value + ", " + investigationLiteral(regexp.QuoteMeta(expected)) + ")"
			}
			unknown := fmt.Sprintf("isnull('%s') OR mvcount('%s') != 1", cond.Field, cond.Field)
			if flag := closedLoopTruncationField(cond.Field); flag != "" {
				unknown += fmt.Sprintf(" OR lower(tostring('%s')) = \"true\" OR tostring('%s') = \"1\"", flag, flag)
			}
			conditions = append(conditions, fmt.Sprintf(`"%s"=case(%s, -1, %s, 1, true(), 0)`, name, unknown, predicate))
			falseTerms = append(falseTerms, "'"+name+"' = 0")
			unknownTerms = append(unknownTerms, "'"+name+"' = -1")
		}
		name := fmt.Sprintf("_aegis_shadow_%s_branch_%d", kind, i)
		branches = append(branches, fmt.Sprintf(`"%s"=case(%s, 0, %s, -1, true(), 1)`, name, strings.Join(falseTerms, " OR "), strings.Join(unknownTerms, " OR ")))
		hits = append(hits, "'"+name+"' = 1")
		unknowns = append(unknowns, "'"+name+"' = -1")
	}
	return " | eval " + strings.Join(conditions, ", ") + " | eval " + strings.Join(branches, ", ") +
		fmt.Sprintf(` | eval "%s"=case(%s, "match", %s, "unknown", true(), "no_match")`, output, strings.Join(hits, " OR "), strings.Join(unknowns, " OR "))
}

func newClosedLoopResult(q Query, baseline, candidate closedloop.Rule, scope string) *ClosedLoopSearchResult {
	b, _ := json.Marshal(baseline)
	c, _ := json.Marshal(candidate)
	return &ClosedLoopSearchResult{Engine: ClosedLoopRuleEngine, Scope: scope,
		BaselineRuleSHA256: closedloop.Hash(b), CandidateRuleSHA256: closedloop.Hash(c),
		CorrelationID: q.CorrelationID, WindowStart: q.Start.UTC(), WindowEnd: q.End.UTC(),
		Events: []ClosedLoopRuleEvent{}, Files: []investigation.FileEvidence{}, Warnings: []string{}}
}

func (out *ClosedLoopSearchResult) warn(warning string) {
	out.Complete = false
	for _, previous := range out.Warnings {
		if previous == warning {
			return
		}
	}
	if len(out.Warnings) < 30 {
		out.Warnings = append(out.Warnings, warning)
	}
}

// FetchClosedLoopRules executes only the generated read-only export search with
// existing reader credentials. Partial/failing query evidence is returned along
// with the error so callers can persist the failed attempt without claiming a miss.
func FetchClosedLoopRules(ctx context.Context, c Config, auth Credentials, q Query, scope investigation.Scope, mapping investigation.Mapping, baseline, candidate closedloop.Rule) (*ClosedLoopSearchResult, error) {
	var err error
	c, err = Validate(c)
	if err != nil {
		return nil, err
	}
	if err = ValidateCredentials(auth); err != nil {
		return nil, err
	}
	search, err := BuildClosedLoopRuleSearch(c, q, scope, mapping, baseline, candidate)
	if err != nil {
		return nil, err
	}
	out := newClosedLoopResult(q, baseline, candidate, "splunk_shadow_rule_evaluation")
	out.Query = search
	out.Warnings = append(out.Warnings, "shadow_matches_are_not_emitted_alerts", "search_completion_does_not_prove_sensor_coverage")
	body, err := closedLoopExport(ctx, c, auth, scope, search, out)
	if len(body) > 0 || err == nil {
		out.Files = append(out.Files, investigation.FileEvidence{Name: "splunk-shadow-export.jsonl", SHA256: closedloop.Hash(body), Bytes: len(body), Content: string(body)})
	}
	if err != nil {
		return out, err
	}
	results, rows, complete, warnings, err := parseInvestigationExport(body)
	out.TotalRows = rows
	out.Complete = complete
	for _, warning := range warnings {
		out.warn(warning)
	}
	if err != nil {
		out.ErrorCode = "invalid_export"
		out.warn("Splunk 검색 응답을 해석하지 못했습니다. 원본 응답을 확인하세요")
		return out, err
	}
	out.Files[0].Rows = rows
	out.Files = append(out.Files, investigation.FileEvidence{Name: "splunk-shadow-events.jsonl", SHA256: closedloop.Hash(results), Bytes: len(results), Rows: rows, Content: string(results)})
	if rows > investigation.MaxRows {
		out.Truncated += rows - investigation.MaxRows
	}
	// Unlike historical hunting, a live no-match needs a completed terminal
	// envelope even for zero rows. Empty/diagnostic-only HTTP 200 is inconclusive.
	if rows == 0 && !closedLoopTerminal(body) {
		out.warn("Splunk 검색의 완료 표시가 없어 빈 결과의 완전성을 확인하지 못했습니다")
	}
	mapping.Timestamp = "_time"
	collection, err := investigation.ParseFiles([]investigation.InputFile{{Name: "splunk-shadow-events.jsonl", Content: string(results)}}, scope, mapping, complete, false, []string{q.CorrelationID})
	if err != nil {
		out.ErrorCode = "invalid_events"
		out.warn("Splunk 원본 이벤트의 범위와 필드 매핑을 확인하지 못했습니다")
		return out, err
	}
	if !collection.Complete {
		out.warn("반환된 이벤트 중 범위·필드·한도를 확인할 수 없는 항목이 있습니다")
	}
	out.Truncated += collection.Stats.Truncated
	if collection.Stats.UnrelatedTarget+collection.Stats.UnrelatedPath+collection.Stats.OutsideWindow > 0 {
		out.warn("설정된 대상·경로·시각 범위 밖의 이벤트가 반환됐습니다")
	}
	seen := map[string]string{}
	auditPairs := make(map[string]bool)
	for _, stream := range c.Streams {
		if stream.Kind == "audit" {
			auditPairs[stream.Index+"\x00"+stream.Sourcetype] = true
		}
	}
	for _, event := range collection.Events {
		if event.VerificationID != q.CorrelationID {
			out.warn("설정된 실행 UUID와 다른 이벤트가 반환됐습니다")
			continue
		}
		fields, fallback, err := closedLoopObjects([]byte(event.Raw))
		index, sourcetype := closedLoopScalar(fields["index"]), closedLoopScalar(fields["sourcetype"])
		if err != nil || !auditPairs[index+"\x00"+sourcetype] {
			out.warn("감사 로그 출처 또는 원본 이벤트 형식을 확인하지 못했습니다")
			continue
		}
		base, cand := closedLoopScalar(fields[baselineShadowField]), closedLoopScalar(fields[candidateShadowField])
		if closedLoopPayloadTruncated(fields, fallback) {
			out.warn("원본 요청 필드가 수집기에서 잘렸습니다. 전체 요청에 대한 규칙 결과는 확인할 수 없습니다")
		}
		if base != matchClosedLoopRule(fields, fallback, baseline) || cand != matchClosedLoopRule(fields, fallback, candidate) {
			out.warn("Splunk 규칙 결과와 원본 필드의 조건 판정이 일치하지 않습니다")
			base, cand = "unknown", "unknown"
		}
		id := closedLoopEventID(fields, fallback, mapping, index, []byte(event.Raw))
		hash := closedloop.Hash([]byte(event.Raw))
		if previous, exists := seen[id]; exists {
			if previous != hash {
				out.warn("같은 원본 이벤트 ID에 서로 다른 로그가 반환됐습니다")
			}
			continue
		}
		seen[id] = hash
		out.Events = append(out.Events, ClosedLoopRuleEvent{EventID: id, OccurredAt: event.Timestamp, Baseline: base, Candidate: cand, Raw: json.RawMessage(event.Raw)})
	}
	return out, nil
}

func closedLoopTerminal(body []byte) bool {
	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 4096), maxResponseBytes)
	terminal := false
	for scan.Scan() {
		if len(bytes.TrimSpace(scan.Bytes())) == 0 {
			continue
		}
		var row struct {
			LastRow bool `json:"lastrow"`
			Preview bool `json:"preview"`
		}
		if decodeInvestigationEnvelope(scan.Bytes(), &row) != nil || row.Preview {
			return false
		}
		terminal = row.LastRow
	}
	return terminal && scan.Err() == nil
}

// Reuse the connector's TLS pin/PKI/redirect/proxy/time limits, but retain a
// bounded successful-response prefix on read/size failures for explicit export.
// Non-200 response bodies are discarded: they are not native log evidence and
// may contain authentication or server diagnostics that must not enter the UI.
func closedLoopExport(ctx context.Context, c Config, auth Credentials, scope investigation.Scope, search string, out *ClosedLoopSearchResult) ([]byte, error) {
	out.QueryStartedAt = time.Now().UTC()
	defer func() {
		out.QueryFinishedAt = time.Now().UTC()
		out.CollectedAt = out.QueryFinishedAt
	}()
	form := url.Values{"search": {search}, "output_mode": {"json"}, "preview": {"false"},
		"output_time_format": {splunkOutputTimeFormat}, "earliest_time": {investigationEpoch(scope.Start)}, "latest_time": {investigationEpoch(scope.End)}}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/services/search/v2/jobs/export", strings.NewReader(form.Encode()))
	if err != nil {
		out.ErrorCode = "invalid_request"
		return nil, errors.New("보안 로그 조회 요청을 만들지 못했습니다")
	}
	if auth.Token != "" {
		r.Header.Set("Authorization", "Bearer "+auth.Token)
	} else {
		r.SetBasicAuth(auth.Username, auth.Password)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	h := client(c)
	defer h.CloseIdleConnections()
	res, err := h.Do(r)
	if err != nil {
		out.ErrorCode = "connection_failed"
		out.warn("Splunk 연결 또는 조회 요청이 완료되지 않았습니다")
		if ctx.Err() != nil {
			out.ErrorCode = "request_cancelled"
			return nil, ctx.Err()
		}
		return nil, errors.New("Splunk 연결에 실패했습니다. 주소·인증서·네트워크를 확인해 주세요")
	}
	defer res.Body.Close()
	out.HTTPStatus = res.StatusCode
	if res.StatusCode != http.StatusOK {
		out.ErrorCode = "http_error"
		out.warn("Splunk가 검색 요청을 거절했습니다")
		return nil, fmt.Errorf("Splunk 조회가 HTTP %d로 거절됐습니다. 연결 계정과 검색 권한을 확인해 주세요", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if len(body) > maxResponseBytes {
		out.Truncated++
		out.ErrorCode = "response_limit"
		out.warn("Splunk 응답이 4 MiB를 초과했습니다. 저장된 응답은 일부입니다")
		return body[:maxResponseBytes], errors.New("Splunk 응답이 4 MiB를 초과했습니다. 조회 범위를 줄여 주세요")
	}
	if err != nil {
		out.ErrorCode = "response_interrupted"
		out.warn("Splunk 응답을 끝까지 읽지 못했습니다. 저장된 응답은 일부입니다")
		return body, errors.New("Splunk 응답을 끝까지 읽지 못했습니다")
	}
	if !utf8.Valid(body) || bytes.ContainsRune(body, 0) {
		out.ErrorCode = "invalid_encoding"
		out.warn("Splunk 응답이 지원하는 UTF-8 로그 형식이 아닙니다")
		return nil, errors.New("Splunk 응답은 NUL 없는 UTF-8이어야 합니다")
	}
	return body, nil
}

func closedLoopObjects(raw []byte) (map[string]any, map[string]any, error) {
	decode := func(raw []byte) (map[string]any, error) {
		if len(raw) > investigation.MaxRecordBytes || !utf8.Valid(raw) {
			return nil, errors.New("invalid record")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		count := 0
		value, err := readUploadJSONValue(d, 0, &count)
		if err != nil {
			return nil, err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid object")
		}
		if _, err = d.Token(); err != io.EOF {
			return nil, errors.New("trailing JSON")
		}
		return object, nil
	}
	fields, err := decode(raw)
	if err != nil {
		return nil, nil, err
	}
	var fallback map[string]any
	if value, ok := fields["_raw"].(string); ok && strings.HasPrefix(strings.TrimSpace(value), "{") {
		fallback, err = decode([]byte(value))
		if err != nil {
			return nil, nil, err
		}
	}
	return fields, fallback, nil
}

func closedLoopValue(fields, fallback map[string]any, key string) any {
	value := field(fields, key)
	if value == nil {
		value = field(fallback, key)
	}
	return value
}

func closedLoopScalar(value any) string {
	text, _ := closedLoopScalarOK(value)
	return text
}

func closedLoopScalarOK(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case json.Number:
		return value.String(), true
	case bool:
		return strconv.FormatBool(value), true
	case []any:
		// Automatic extraction + spath can repeat one scalar. Conflicting
		// multivalues remain unknown rather than selecting a favorable value.
		if len(value) == 0 {
			return "", false
		}
		first, ok := closedLoopScalarOK(value[0])
		if _, nested := value[0].([]any); nested {
			return "", false
		}
		if !ok {
			return "", false
		}
		for _, child := range value[1:] {
			if _, nested := child.([]any); nested {
				return "", false
			}
			text, valid := closedLoopScalarOK(child)
			if !valid || text != first {
				return "", false
			}
		}
		return first, true
	}
	return "", false
}

func matchClosedLoopRule(fields, fallback map[string]any, rule closedloop.Rule) string {
	unknown := false
	for _, branch := range rule.Any {
		branchUnknown, branchFalse := false, false
		for _, cond := range branch.All {
			if flag := closedLoopTruncationField(cond.Field); flag != "" && closedLoopTrue(closedLoopValue(fields, fallback, flag)) {
				branchUnknown = true
				continue
			}
			value, ok := closedLoopScalarOK(closedLoopValue(fields, fallback, cond.Field))
			if !ok {
				branchUnknown = true
				continue
			}
			expected := cond.Value
			if !cond.CaseSensitive {
				value, expected = strings.ToLower(value), strings.ToLower(expected)
			}
			hit := value == expected
			if cond.Op == "contains" {
				hit = strings.Contains(value, expected)
			}
			branchFalse = branchFalse || !hit
		}
		if !branchFalse && !branchUnknown {
			return "match"
		}
		unknown = unknown || !branchFalse && branchUnknown
	}
	if unknown {
		return "unknown"
	}
	return "no_match"
}

func closedLoopTruncationField(field string) string {
	switch field {
	case "path", "request_target", "query_string":
		return field + "_truncated"
	}
	return ""
}

func closedLoopTrue(value any) bool {
	text, ok := closedLoopScalarOK(value)
	return ok && (strings.EqualFold(text, "true") || text == "1")
}

func closedLoopPayloadTruncated(fields, fallback map[string]any) bool {
	for _, f := range []string{"path_truncated", "request_target_truncated", "query_string_truncated"} {
		if closedLoopTrue(closedLoopValue(fields, fallback, f)) {
			return true
		}
	}
	return false
}

func closedLoopEventID(fields, fallback map[string]any, mapping investigation.Mapping, index string, raw []byte) string {
	// Prefer source's native event ID so it joins to audit_event_id in alerts.
	if id := closedLoopScalar(closedLoopValue(fields, fallback, mapping.EventID)); id != "" {
		return id
	}
	if id := closedLoopScalar(fields["_cd"]); id != "" {
		return index + ":" + closedLoopScalar(fields["splunk_server"]) + ":" + closedLoopScalar(fields["_bkt"]) + ":" + id
	}
	return "sha256:" + closedloop.Hash(raw)
}

// EvaluateClosedLoopFile evaluates previously collected uploaded audit evidence.
// It preserves the original upload provenance; it does not call Splunk, emit an
// alert, run an attack, or infer that uploading a matching log means detection.
func EvaluateClosedLoopFile(c Config, q Query, scope investigation.Scope, mapping investigation.Mapping, baseline, candidate closedloop.Rule, evidence *Evidence) (*ClosedLoopSearchResult, error) {
	if evidence == nil || evidence.Upload == nil {
		return nil, fmt.Errorf("%w: 원본 업로드 증거가 필요합니다", ErrInvalid)
	}
	if err := validateClosedLoopScope(c, q, scope, mapping); err != nil {
		return nil, err
	}
	if err := validateClosedLoopRules(mapping, baseline, candidate); err != nil {
		return nil, err
	}
	if len(evidence.Upload.Files) == 0 || len(evidence.Upload.Files) > 2 {
		return nil, fmt.Errorf("%w: 원본 감사·경보 업로드 파일이 필요합니다", ErrInvalid)
	}
	total := 0
	for _, file := range evidence.Upload.Files {
		total += len(file.Content)
		if total > MaxUploadBytes || file.Bytes != len(file.Content) || file.SHA256 != closedloop.Hash([]byte(file.Content)) {
			return nil, fmt.Errorf("%w: 업로드 파일 원문·크기·해시를 확인할 수 없습니다", ErrInvalid)
		}
	}
	// Result sanitization/export must never mutate the stored original upload.
	uploadJSON, err := json.Marshal(evidence.Upload)
	if err != nil {
		return nil, fmt.Errorf("%w: 업로드 증거를 보존하지 못했습니다", ErrInvalid)
	}
	var upload UploadProvenance
	if err = json.Unmarshal(uploadJSON, &upload); err != nil {
		return nil, fmt.Errorf("%w: 업로드 증거를 보존하지 못했습니다", ErrInvalid)
	}
	out := newClosedLoopResult(q, baseline, candidate, "file_rule_evaluation")
	out.Engine = "file-shadow-exact-contains-v1"
	out.Complete, out.CollectedAt, out.Upload = evidence.Complete, evidence.CollectedAt, &upload
	out.Warnings = append(out.Warnings, "file_matches_are_not_emitted_alerts", "upload_provenance_attested_by_uploader")
	for _, warning := range evidence.Warnings {
		out.warn(warning)
	}
	if evidence.WindowStart.After(q.Start) || evidence.WindowEnd.Before(q.End) {
		out.warn("업로드 증거가 실행 전체 조회 구간을 포함하지 않습니다")
	}
	out.Truncated = evidence.Upload.Stats.Truncated
	seen := map[string]string{}
	for _, event := range evidence.Events {
		if event.Kind != "audit" {
			continue
		}
		out.TotalRows++
		if out.TotalRows > investigation.MaxEvents {
			out.Truncated++
			out.warn("파일 규칙 평가의 이벤트 보존 한도를 초과했습니다")
			continue
		}
		fields, fallback, err := closedLoopObjects(event.Raw)
		if err != nil {
			out.warn("파일 원본 이벤트를 해석하지 못했습니다")
			continue
		}
		if event.CorrelationID != q.CorrelationID || event.OccurredAt.Before(q.Start) || !event.OccurredAt.Before(q.End) ||
			closedLoopScalar(closedLoopValue(fields, fallback, mapping.VerificationID)) != q.CorrelationID ||
			!investigation.MatchTarget(closedLoopScalar(closedLoopValue(fields, fallback, mapping.Target)), scope.Target) ||
			!investigation.MatchPath(closedLoopScalar(closedLoopValue(fields, fallback, mapping.Path)), scope.PathPrefix) {
			out.warn("실행 UUID·대상·경로·시각 범위와 맞지 않는 파일 이벤트가 있습니다")
			continue
		}
		if previous, exists := seen[event.ID]; exists {
			if previous != closedloop.Hash(event.Raw) {
				out.warn("같은 파일 이벤트 ID에 서로 다른 로그가 있습니다")
			}
			continue
		}
		seen[event.ID] = closedloop.Hash(event.Raw)
		if closedLoopPayloadTruncated(fields, fallback) {
			out.warn("파일 원본 요청 필드가 잘렸습니다. 전체 요청에 대한 규칙 결과는 확인할 수 없습니다")
		}
		out.Events = append(out.Events, ClosedLoopRuleEvent{EventID: event.ID, OccurredAt: event.OccurredAt,
			Baseline: matchClosedLoopRule(fields, fallback, baseline), Candidate: matchClosedLoopRule(fields, fallback, candidate), Raw: append(json.RawMessage(nil), event.Raw...)})
	}
	return out, nil
}
