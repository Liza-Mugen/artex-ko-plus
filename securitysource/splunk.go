// Package securitysource reads correlated observations from a configured SIEM.
// It never creates alerts, executes caller-supplied SPL, or changes remote rules.
package securitysource

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid           = errors.New("보안 로그 연결 설정이 올바르지 않습니다")
	ErrSplunkAuth        = errors.New("Splunk 인증에 실패했습니다")
	ErrSplunkPermission  = errors.New("Splunk 조회 권한이 없습니다")
	ErrSplunkUnavailable = errors.New("Splunk 연결 또는 서비스에 실패했습니다")
	ErrSplunkSearch      = errors.New("Splunk 검색을 완료하지 못했습니다")
)

// LogStream is one explicitly configured, read-only Splunk search source.
// A connection may contain audit and alert streams in different indexes.
type LogStream struct {
	Index      string `json:"index"`
	Sourcetype string `json:"sourcetype"`
	Kind       string `json:"kind"`
	Label      string `json:"label,omitempty"`
	Asset      string `json:"asset,omitempty"`
}

type Config struct {
	BaseURL          string      `json:"base_url"`
	Index            string      `json:"index"`
	AuditSourcetype  string      `json:"audit_sourcetype"`
	AlertSourcetype  string      `json:"alert_sourcetype"`
	Streams          []LogStream `json:"streams,omitempty"`
	CorrelationField string      `json:"correlation_field"`
	ActionField      string      `json:"action_field"`
	TLSFingerprint   string      `json:"tls_fingerprint"`
}
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}
type Query struct {
	CorrelationID string
	Start, End    time.Time
}
type Event struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Index         string          `json:"index,omitempty"`
	Sourcetype    string          `json:"sourcetype,omitempty"`
	CorrelationID string          `json:"correlation_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	Action        string          `json:"action"`
	Raw           json.RawMessage `json:"raw"`
	FileName      string          `json:"file_name,omitempty"`
	Line          int             `json:"line,omitempty"`
}
type Evidence struct {
	Events      []Event           `json:"events"`
	Complete    bool              `json:"complete"`
	CollectedAt time.Time         `json:"collected_at"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
	Warnings    []string          `json:"warnings"`
	Upload      *UploadProvenance `json:"upload,omitempty"`
	Diagnostics []Diagnostic      `json:"diagnostics,omitempty"`
}

var sourceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`)
var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
var correlationName = regexp.MustCompile(`^[A-Za-z0-9-]{16,80}$`)

const maxResponseBytes = 4 << 20
const maxRows = 200
const maxLogStreams = 16

// An explicit numeric offset avoids the ambiguous timezone abbreviations used
// by Splunk's default export format. Preserve microsecond request timestamps.
const splunkOutputTimeFormat = "%Y-%m-%dT%H:%M:%S.%6N%z"

// Splunk's automatic field extraction and spath can extract the same scalar
// twice. Keep automatic fields for non-JSON sources and remove exact duplicates
// only; distinct values stay multivalued for the local parsers to reject.
// Callers validate every field name before constructing a search.
func splunkDeduplicateFields(fields ...string) string {
	seen := make(map[string]bool, len(fields))
	expressions := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		// eval assignment targets need double quotes; single quotes create a
		// literal quote-bearing field instead of updating the extracted field.
		expressions = append(expressions, fmt.Sprintf(`"%s"=mvdedup('%s')`, field, field))
	}
	if len(expressions) == 0 {
		return ""
	}
	return " | eval " + strings.Join(expressions, ", ")
}

func Validate(c Config) (Config, error) {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return c, fmt.Errorf("%w: HTTPS 관리 주소만 입력해 주세요 (경로·계정·쿼리 제외)", ErrInvalid)
	}
	if len(c.Streams) == 0 {
		if !sourceName.MatchString(c.Index) || !sourceName.MatchString(c.AuditSourcetype) || !sourceName.MatchString(c.AlertSourcetype) || c.AuditSourcetype == c.AlertSourcetype {
			return c, fmt.Errorf("%w: 인덱스와 서로 다른 감사·경보 sourcetype이 필요합니다", ErrInvalid)
		}
		c.Streams = EffectiveStreams(c)
	} else {
		c.Streams = slices.Clone(c.Streams)
		// Legacy scalars may accompany a newer stream list, but invalid values
		// must not be silently accepted or later used by an older workflow.
		for _, value := range []string{c.Index, c.AuditSourcetype, c.AlertSourcetype} {
			if value != "" && !sourceName.MatchString(value) {
				return c, fmt.Errorf("%w: 이전 형식의 인덱스·sourcetype 이름을 확인해 주세요", ErrInvalid)
			}
		}
	}
	if len(c.Streams) > maxLogStreams {
		return c, fmt.Errorf("%w: 로그 스트림은 최대 16개까지 등록할 수 있습니다", ErrInvalid)
	}
	seen := make(map[string]bool, len(c.Streams))
	hasAudit, hasAlert := false, false
	for i := range c.Streams {
		s := &c.Streams[i]
		s.Label, s.Asset = strings.TrimSpace(s.Label), strings.TrimSpace(s.Asset)
		if !sourceName.MatchString(s.Index) || !sourceName.MatchString(s.Sourcetype) || (s.Kind != "audit" && s.Kind != "alert") ||
			!safeStreamDescription(s.Label, 120) || !safeStreamDescription(s.Asset, 256) {
			return c, fmt.Errorf("%w: 로그 스트림의 인덱스·sourcetype·종류·표시 이름을 확인해 주세요", ErrInvalid)
		}
		key := s.Index + "\x00" + s.Sourcetype
		if seen[key] {
			return c, fmt.Errorf("%w: 중복된 로그 스트림이 있습니다", ErrInvalid)
		}
		seen[key] = true
		hasAudit = hasAudit || s.Kind == "audit"
		hasAlert = hasAlert || s.Kind == "alert"
	}
	if !hasAudit || !hasAlert {
		return c, fmt.Errorf("%w: 감사·경보 로그 스트림이 각각 하나 이상 필요합니다", ErrInvalid)
	}
	if !fieldName.MatchString(c.CorrelationField) || !fieldName.MatchString(c.ActionField) {
		return c, fmt.Errorf("%w: 상관 ID·조치 필드 이름을 확인해 주세요", ErrInvalid)
	}
	c.TLSFingerprint = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.TLSFingerprint), ":", ""))
	if c.TLSFingerprint != "" {
		b, e := hex.DecodeString(c.TLSFingerprint)
		if e != nil || len(b) != 32 {
			return c, fmt.Errorf("%w: 인증서 SHA-256은 64자리 16진수여야 합니다", ErrInvalid)
		}
	}
	return c, nil
}

func safeStreamDescription(value string, maxRunes int) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= maxRunes && strings.IndexFunc(value, unicode.IsControl) < 0
}

// EffectiveStreams resolves the two legacy sourcetypes without changing the
// saved config. Call Validate before using these values in a remote query.
func EffectiveStreams(c Config) []LogStream {
	if len(c.Streams) != 0 {
		return slices.Clone(c.Streams)
	}
	return []LogStream{
		{Index: c.Index, Sourcetype: c.AuditSourcetype, Kind: "audit"},
		{Index: c.Index, Sourcetype: c.AlertSourcetype, Kind: "alert"},
	}
}

// EqualConfig compares the effective search behavior. Migrating unchanged
// legacy index fields into streams must not stale an execution or bump a
// connection revision merely because the JSON representation changed.
func EqualConfig(a, b Config) bool {
	return a.BaseURL == b.BaseURL && a.CorrelationField == b.CorrelationField &&
		a.ActionField == b.ActionField && a.TLSFingerprint == b.TLSFingerprint &&
		slices.Equal(EffectiveStreams(a), EffectiveStreams(b))
}
func ValidateCredentials(c Credentials) error {
	if c.Token != "" {
		if c.Username != "" || c.Password != "" || len(c.Token) > 8192 || strings.ContainsAny(c.Token, "\r\n\x00") {
			return fmt.Errorf("%w: 토큰 또는 계정 인증 중 하나를 사용해 주세요", ErrInvalid)
		}
		return nil
	}
	if c.Username == "" || c.Password == "" || len(c.Username) > 256 || len(c.Password) > 8192 || strings.ContainsAny(c.Username, ":\r\n\x00") || strings.ContainsRune(c.Password, 0) {
		return fmt.Errorf("%w: 연결 계정과 비밀번호가 필요합니다", ErrInvalid)
	}
	return nil
}

func client(c Config) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSFingerprint != "" {
		pin, _ := hex.DecodeString(c.TLSFingerprint)
		// A configured exact leaf-certificate pin replaces PKI validation. It
		// does not allow arbitrary self-signed certificates or redirects.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("인증서가 없습니다")
			}
			cert := cs.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			now := time.Now()
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("서버 인증서가 저장된 핀과 일치하지 않거나 만료됐습니다")
			}
			return nil
		}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: tc, DisableKeepAlives: true, ResponseHeaderTimeout: 15 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func request(ctx context.Context, c Config, auth Credentials, path string, form url.Values) ([]byte, error) {
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method = http.MethodPost
		body = strings.NewReader(form.Encode())
	}
	r, e := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if e != nil {
		return nil, errors.New("보안 로그 조회 요청을 만들지 못했습니다")
	}
	if auth.Token != "" {
		r.Header.Set("Authorization", "Bearer "+auth.Token)
	} else {
		r.SetBasicAuth(auth.Username, auth.Password)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("Accept", "application/json")
	h := client(c)
	defer h.CloseIdleConnections()
	res, e := h.Do(r)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: 주소·인증서·네트워크를 확인해 주세요", ErrSplunkUnavailable)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, ErrSplunkAuth
		case http.StatusForbidden:
			return nil, ErrSplunkPermission
		}
		if res.StatusCode >= http.StatusInternalServerError {
			return nil, ErrSplunkUnavailable
		}
		return nil, fmt.Errorf("Splunk 조회가 HTTP %d로 거절됐습니다. 연결 계정과 검색 권한을 확인해 주세요", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if e != nil {
		return nil, errors.New("Splunk 응답을 끝까지 읽지 못했습니다")
	}
	if len(b) > maxResponseBytes {
		return nil, errors.New("Splunk 응답이 4 MiB를 초과했습니다. 조회 범위를 줄여 주세요")
	}
	return b, nil
}

func Test(ctx context.Context, c Config, auth Credentials) error {
	c, e := Validate(c)
	if e != nil {
		return e
	}
	if e = ValidateCredentials(auth); e != nil {
		return e
	}
	b, e := request(ctx, c, auth, "/services/server/info?output_mode=json", nil)
	if e != nil {
		return e
	}
	var v struct {
		Entry []json.RawMessage `json:"entry"`
	}
	if json.Unmarshal(b, &v) != nil || len(v.Entry) == 0 {
		return errors.New("Splunk 서버 정보 응답을 확인하지 못했습니다")
	}
	return nil
}

// ListIndexes reads the indexes visible to this credential through Splunk's
// management API. The response is sorted, allowlisted, and capped for the UI.
func ListIndexes(ctx context.Context, c Config, auth Credentials) ([]string, error) {
	var err error
	c, err = Validate(c)
	if err != nil {
		return nil, err
	}
	if err = ValidateCredentials(auth); err != nil {
		return nil, err
	}
	const limit = 128
	body, err := request(ctx, c, auth, "/services/data/indexes?output_mode=json&count=128", nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Entry []struct {
			Name string `json:"name"`
		} `json:"entry"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Entry == nil {
		return nil, fmt.Errorf("%w: 인덱스 목록 응답 형식을 확인하지 못했습니다", ErrSplunkSearch)
	}
	indexes := make([]string, 0, min(len(payload.Entry), limit))
	seen := make(map[string]bool)
	for _, entry := range payload.Entry {
		if !sourceName.MatchString(entry.Name) || seen[entry.Name] {
			continue
		}
		seen[entry.Name] = true
		indexes = append(indexes, entry.Name)
		if len(indexes) == limit {
			break
		}
	}
	slices.Sort(indexes)
	return indexes, nil
}

type StreamTestResult struct {
	Index           string `json:"index"`
	Sourcetype      string `json:"sourcetype"`
	Kind            string `json:"kind"`
	Searchable      bool   `json:"searchable"`
	HasRecentEvents bool   `json:"has_recent_events"`
	Detail          string `json:"detail"`
}

// TestStream probes one configured stream with a read-only 15-minute search.
// A completed zero-result search is distinguishable from a rejected or partial
// search; neither proves long-term retention or sensor coverage.
func TestStream(ctx context.Context, c Config, auth Credentials, streamIndex int) (StreamTestResult, error) {
	var result StreamTestResult
	var err error
	c, err = Validate(c)
	if err != nil {
		return result, err
	}
	if err = ValidateCredentials(auth); err != nil {
		return result, err
	}
	if streamIndex < 0 || streamIndex >= len(c.Streams) {
		return result, fmt.Errorf("%w: 로그 스트림 번호를 확인해 주세요", ErrInvalid)
	}
	s := c.Streams[streamIndex]
	result.Index, result.Sourcetype, result.Kind = s.Index, s.Sourcetype, s.Kind
	now := time.Now().UTC()
	search := fmt.Sprintf(`search index="%s" sourcetype="%s" | head 1`, s.Index, s.Sourcetype)
	body, err := request(ctx, c, auth, "/services/search/v2/jobs/export", url.Values{
		"search": {search}, "output_mode": {"json"}, "preview": {"false"},
		"earliest_time": {investigationEpoch(now.Add(-15 * time.Minute))}, "latest_time": {investigationEpoch(now)},
	})
	if err != nil {
		return result, err
	}
	_, rows, complete, _, err := parseInvestigationExport(body)
	if err != nil || !complete || !closedLoopTerminal(body) || rows > 1 {
		return result, fmt.Errorf("%w: 로그 스트림의 완료된 검색 결과를 확인하지 못했습니다", ErrSplunkSearch)
	}
	result.Searchable = true
	result.HasRecentEvents = rows == 1
	if result.HasRecentEvents {
		result.Detail = "최근 15분 이내 이벤트 1건을 확인했습니다"
	} else {
		result.Detail = "검색은 완료됐지만 최근 15분 이내 이벤트는 없습니다"
	}
	return result, nil
}

func Fetch(ctx context.Context, c Config, auth Credentials, q Query) (*Evidence, error) {
	c, e := Validate(c)
	if e != nil {
		return nil, e
	}
	if e = ValidateCredentials(auth); e != nil {
		return nil, e
	}
	if !correlationName.MatchString(q.CorrelationID) || q.Start.IsZero() || !q.End.After(q.Start) || q.End.Sub(q.Start) > 24*time.Hour || q.End.After(time.Now().Add(5*time.Second)) {
		return nil, fmt.Errorf("%w: 실행 식별자 또는 조회 시간 범위를 확인해 주세요 (최대 24시간)", ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}, WindowStart: q.Start.UTC(), WindowEnd: q.End.UTC()}
	seen := make(map[string][32]byte)
	for _, s := range c.Streams {
		// Names have restrictive allowlists, and the correlation ID is generated
		// by ARTEX. No free-form query or state-changing command is accepted.
		search := fmt.Sprintf(`search index="%s" sourcetype="%s" | spath%s | where '%s' = "%s" | head %d`, s.Index, s.Sourcetype, splunkDeduplicateFields(c.CorrelationField, c.ActionField), c.CorrelationField, q.CorrelationID, maxRows+1)
		b, e := request(ctx, c, auth, "/services/search/v2/jobs/export", url.Values{"search": {search}, "output_mode": {"json"}, "output_time_format": {splunkOutputTimeFormat}, "earliest_time": {strconv.FormatFloat(float64(q.Start.UnixNano())/1e9, 'f', 6, 64)}, "latest_time": {strconv.FormatFloat(float64(q.End.UnixNano())/1e9, 'f', 6, 64)}, "preview": {"false"}})
		if e != nil {
			return nil, e
		}
		if e = parseStreamExport(b, s, c, q, out, seen); e != nil {
			return nil, e
		}
	}
	out.CollectedAt = time.Now().UTC()
	return out, nil
}

func field(m map[string]any, name string) any {
	if v, ok := m[name]; ok {
		return v
	}
	var v any = m
	for _, p := range strings.Split(name, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = obj[p]
	}
	return v
}
func textField(v any) string { s, _ := v.(string); return s }
func eventTime(v any) (time.Time, error) {
	s := fmt.Sprint(v)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if t, e := time.Parse(layout, s); e == nil {
			return t.UTC(), nil
		}
	}
	if n, e := strconv.ParseFloat(s, 64); e == nil && n > 0 && n < 1e11 {
		return time.Unix(int64(n), int64((n-math.Floor(n))*1e9)).UTC(), nil
	}
	return time.Time{}, errors.New("시각이 올바르지 않습니다")
}
func parseExport(b []byte, kind string, c Config, q Query, out *Evidence) error {
	s := LogStream{Index: c.Index, Kind: kind}
	if kind == "audit" {
		s.Sourcetype = c.AuditSourcetype
	} else {
		s.Sourcetype = c.AlertSourcetype
	}
	return parseStreamExport(b, s, c, q, out, make(map[string][32]byte))
}

func parseStreamExport(b []byte, stream LogStream, c Config, q Query, out *Evidence, seen map[string][32]byte) error {
	scan := bufio.NewScanner(strings.NewReader(string(b)))
	scan.Buffer(make([]byte, 4096), maxResponseBytes)
	count := 0
	lastResultComplete, sawTerminal := false, false
	for scan.Scan() {
		if strings.TrimSpace(scan.Text()) == "" {
			continue
		}
		var row struct {
			Result   map[string]any `json:"result"`
			Preview  bool           `json:"preview"`
			LastRow  bool           `json:"lastrow"`
			Messages []struct {
				Type string `json:"type"`
			} `json:"messages"`
			Error any `json:"error"`
		}
		decoder := json.NewDecoder(strings.NewReader(scan.Text()))
		decoder.UseNumber()
		if decoder.Decode(&row) != nil {
			return errors.New("Splunk 검색 응답 형식이 올바르지 않습니다")
		}
		if row.Error != nil {
			return errors.New("Splunk 검색에 실패했습니다")
		}
		for _, msg := range row.Messages {
			switch strings.ToUpper(msg.Type) {
			case "ERROR", "FATAL":
				return errors.New("Splunk 검색이 완료되지 않았습니다")
			case "WARN", "WARNING":
				out.Complete = false
				out.Warnings = append(out.Warnings, "Splunk가 검색 경고를 반환했습니다. 누락 여부를 확인해야 합니다")
			case "INFO", "DEBUG":
			default:
				out.Complete = false
				out.Warnings = append(out.Warnings, "Splunk 검색 진단의 종류를 확인하지 못했습니다")
			}
		}
		if row.Preview {
			out.Complete = false
			out.Warnings = append(out.Warnings, "Splunk 미리보기 결과는 완료된 검색으로 판정하지 않습니다")
			continue
		}
		if row.Result == nil {
			// An actual completed zero-result export sends only preview:false
			// and lastrow:true. It is not a missing or malformed event.
			if row.LastRow {
				sawTerminal = true
			} else if len(row.Messages) == 0 {
				out.Complete = false
				out.Warnings = append(out.Warnings, "검색 결과 형식이 확인되지 않아 판정을 보류합니다")
			}
			continue
		}
		count++
		lastResultComplete, sawTerminal = row.LastRow, false
		if count > maxRows {
			out.Complete = false
			out.Warnings = append(out.Warnings, stream.Kind+" 검색이 200건을 초과하여 판정을 보류합니다")
			continue
		}
		m := row.Result
		if index, present := m["index"]; present && textField(index) != stream.Index {
			out.Complete = false
			out.Warnings = append(out.Warnings, "설정된 인덱스 밖의 이벤트가 반환됐습니다")
			continue
		}
		if st, present := m["sourcetype"]; present && stream.Sourcetype != "" && textField(st) != stream.Sourcetype {
			out.Complete = false
			out.Warnings = append(out.Warnings, "설정된 sourcetype 밖의 이벤트가 반환됐습니다")
			continue
		}
		var raw map[string]any
		if s, ok := m["_raw"].(string); ok {
			d := json.NewDecoder(strings.NewReader(s))
			d.UseNumber()
			_ = d.Decode(&raw)
		}
		correlation := field(m, c.CorrelationField)
		if correlation == nil {
			correlation = field(raw, c.CorrelationField)
		}
		t, te := eventTime(m["_time"])
		if textField(correlation) != q.CorrelationID || te != nil || t.Before(q.Start) || !t.Before(q.End) {
			out.Complete = false
			out.Warnings = append(out.Warnings, "실행 식별자 또는 조회 시각이 맞지 않는 이벤트가 반환됐습니다")
			continue
		}
		payload, e := json.Marshal(m)
		if e != nil {
			return errors.New("로그 원문을 보존하지 못했습니다")
		}
		if len(payload) > 128<<10 || strings.Contains(string(payload), `\u0000`) {
			out.Complete = false
			out.Warnings = append(out.Warnings, "보존 한도를 넘거나 지원하지 않는 문자가 있는 이벤트가 제외됐습니다")
			continue
		}
		id := textField(m["_cd"])
		sum := sha256.Sum256(payload)
		if id == "" {
			id = hex.EncodeToString(sum[:])
		}
		id = stream.Index + ":" + textField(m["splunk_server"]) + ":" + textField(m["_bkt"]) + ":" + id
		identity := stream.Kind + "\x00" + id
		if previous, exists := seen[identity]; exists {
			if previous != sum {
				out.Complete = false
				out.Warnings = append(out.Warnings, "같은 이벤트 ID에 서로 다른 근거가 반환되어 판정을 보류합니다")
			}
			continue
		}
		seen[identity] = sum
		a := field(m, c.ActionField)
		if a == nil {
			a = field(raw, c.ActionField)
		}
		action := "unknown"
		switch strings.ToLower(textField(a)) {
		case "block", "blocked", "deny", "denied":
			action = "blocked"
		case "allow", "allowed", "pass", "passed":
			action = "allowed"
		}
		if len(out.Events) >= maxRows {
			out.Complete = false
			out.Warnings = append(out.Warnings, "전체 로그가 200건을 초과하여 판정을 보류합니다")
			continue
		}
		out.Events = append(out.Events, Event{ID: id, Kind: stream.Kind, Index: stream.Index, Sourcetype: stream.Sourcetype, CorrelationID: q.CorrelationID, OccurredAt: t, Action: action, Raw: payload})
	}
	if scan.Err() != nil {
		return errors.New("Splunk 검색 응답이 잘렸습니다")
	}
	if (count > 0 && !lastResultComplete && !sawTerminal) || (count == 0 && !sawTerminal) {
		out.Complete = false
		out.Warnings = append(out.Warnings, "Splunk 검색의 마지막 결과 표시가 없어 조회 완료를 확인하지 못했습니다")
	}
	return nil
}
