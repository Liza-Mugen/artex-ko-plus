package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
)

type defensiveCaseRequest struct {
	Title                     string                    `json:"title"`
	Question                  string                    `json:"question"`
	Scope                     investigation.Scope       `json:"scope"`
	Mapping                   investigation.Mapping     `json:"mapping"`
	SourceKind                string                    `json:"source_kind"`
	FileLabel                 string                    `json:"file_label"`
	Files                     []investigation.InputFile `json:"files"`
	SourceID                  int64                     `json:"source_id,string"`
	ExpectedSourceRevision    int64                     `json:"expected_source_revision"`
	Sourcetypes               []string                  `json:"sourcetypes"`
	CoverageConfirmed         bool                      `json:"coverage_confirmed"`
	TargetScopeConfirmed      bool                      `json:"target_scope_confirmed"`
	FindingID                 int64                     `json:"finding_id,string"`
	ExpectedEvidenceVersion   *int64                    `json:"expected_evidence_version"`
	ExpectedSourceFingerprint string                    `json:"expected_source_fingerprint"`
}

func (s *Server) registerDefensiveCases(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/defensive/cases", s.listDefensiveCases)
	mux.HandleFunc("POST /api/defensive/cases", s.createDefensiveCase)
	mux.HandleFunc("POST /api/defensive/cases/preview", s.previewDefensiveCase)
	mux.HandleFunc("GET /api/defensive/cases/{id}", s.getDefensiveCase)
	mux.HandleFunc("DELETE /api/defensive/cases/{id}", s.deleteDefensiveCase)
	mux.HandleFunc("GET /api/defensive/cases/{id}/export", s.exportDefensiveCase)
	s.registerDefensiveCaseRuns(mux)
}

func defensiveCaseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrDefensiveCaseNotFound), errors.Is(err, db.ErrDefensiveCaseRunNotFound):
		writeErr(w, 404, err.Error())
	case errors.Is(err, db.ErrDefensiveCaseRunInactive), errors.Is(err, db.ErrDefensiveCaseActive):
		writeErr(w, 409, err.Error())
	default:
		investigationError(w, err)
	}
}

func validateDefensiveCaseRequest(in defensiveCaseRequest) error {
	if in.SourceKind != "file" && in.SourceKind != "splunk" {
		return fmt.Errorf("로그 연결 방식을 선택해 주세요")
	}
	if err := investigation.ValidateScope(in.Scope, time.Now()); err != nil {
		return err
	}
	if err := investigation.ValidateMapping(in.Mapping); err != nil {
		return err
	}
	if len([]rune(in.Title)) > 200 || len([]rune(in.Question)) > 4000 || strings.ContainsRune(in.Title+in.Question, 0) {
		return fmt.Errorf("제목은 200자, 조사 질문은 4000자 이내로 입력해 주세요")
	}
	if in.FindingID > 0 {
		if in.ExpectedEvidenceVersion == nil || *in.ExpectedEvidenceVersion < 0 || len(in.ExpectedSourceFingerprint) != 32 {
			return fmt.Errorf("연결할 취약점 근거를 새로고침해 주세요")
		}
	} else if in.FindingID < 0 || in.ExpectedEvidenceVersion != nil || in.ExpectedSourceFingerprint != "" {
		return fmt.Errorf("취약점 연결 없이 근거 버전을 지정할 수 없습니다")
	}
	if in.SourceKind == "file" {
		if in.SourceID != 0 || in.ExpectedSourceRevision != 0 || len(in.Sourcetypes) > 0 {
			return fmt.Errorf("파일 조사에는 Splunk 연결을 지정하지 않습니다")
		}
		if len([]rune(strings.TrimSpace(in.FileLabel))) < 1 || len([]rune(in.FileLabel)) > 120 || strings.ContainsRune(in.FileLabel, 0) {
			return fmt.Errorf("파일 로그 출처 이름을 1~120자로 입력해 주세요")
		}
	} else if in.SourceID <= 0 || in.ExpectedSourceRevision <= 0 || len(in.Files) > 0 {
		return fmt.Errorf("활성 Splunk 연결을 선택하고 파일은 별도로 조사해 주세요")
	}
	return nil
}

func normalizeDefensiveCaseMapping(in *defensiveCaseRequest) {
	if in.Mapping == (investigation.Mapping{}) {
		in.Mapping = investigation.DefaultMapping()
	}
}

func (s *Server) listDefensiveCases(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.ListDefensiveCases(r.Context())
	if err != nil {
		defensiveCaseError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}

func (s *Server) checkDefensiveCaseLink(ctx context.Context, pg *db.DB, in defensiveCaseRequest) error {
	if in.FindingID == 0 {
		return nil
	}
	overview, err := pg.GetInvestigationOverview(ctx, in.FindingID)
	if err != nil {
		return err
	}
	if in.ExpectedEvidenceVersion == nil || overview.EvidenceVersion != *in.ExpectedEvidenceVersion || overview.SourceFingerprint != in.ExpectedSourceFingerprint {
		return db.ErrDefenseConflict
	}
	return nil
}

func (s *Server) previewDefensiveCase(w http.ResponseWriter, r *http.Request) {
	var in defensiveCaseRequest
	if !decodePurpleRequestLimit(w, r, &in, 128<<10) {
		return
	}
	normalizeDefensiveCaseMapping(&in)
	if err := validateDefensiveCaseRequest(in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.SourceKind != "splunk" {
		writeErr(w, 400, "검색 미리보기는 Splunk 연결에서 사용할 수 있습니다")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := s.checkDefensiveCaseLink(r.Context(), pg, in); err != nil {
		defensiveCaseError(w, err)
		return
	}
	source, err := s.investigationSource(r.Context(), pg, investigationRequest{SourceID: in.SourceID, ExpectedSourceRevision: in.ExpectedSourceRevision})
	if err != nil {
		defensiveCaseError(w, err)
		return
	}
	query, err := securitysource.BuildInvestigationSearch(source.Config, in.Scope, in.Mapping, in.Sourcetypes)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"query": query, "source_revision": source.Revision, "scope": in.Scope, "limits": map[string]any{"max_days": 31, "max_bytes": investigation.MaxUploadBytes, "max_response_bytes": 4 << 20, "max_rows": investigation.MaxRows, "max_events": investigation.MaxEvents}})
}

func (s *Server) createDefensiveCase(w http.ResponseWriter, r *http.Request) {
	var in defensiveCaseRequest
	if !decodePurpleRequestLimit(w, r, &in, 32<<20) {
		return
	}
	normalizeDefensiveCaseMapping(&in)
	if err := validateDefensiveCaseRequest(in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := s.checkDefensiveCaseLink(r.Context(), pg, in); err != nil {
		defensiveCaseError(w, err)
		return
	}
	// All registered test runs are relevant even when no finding has been linked.
	knownRuns, err := pg.KnownDefensiveVerifications(r.Context(), in.Scope)
	if err != nil {
		defensiveCaseError(w, err)
		return
	}
	known := []string{}
	for _, run := range knownRuns {
		known = append(known, run.ID)
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = "로그 기반 방어 조사"
	}
	out := db.DefensiveCase{Title: title, Question: in.Question, Scope: in.Scope, Mapping: in.Mapping, SourceKind: in.SourceKind, SourceID: in.SourceID, SourceRevision: in.ExpectedSourceRevision, FindingID: in.FindingID, SourceFingerprint: in.ExpectedSourceFingerprint}
	if in.ExpectedEvidenceVersion != nil {
		out.EvidenceVersion = *in.ExpectedEvidenceVersion
	}
	if in.SourceKind == "file" {
		out.Collection, err = investigation.ParseFiles(in.Files, in.Scope, in.Mapping, in.CoverageConfirmed, in.TargetScopeConfirmed, known)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		out.SourceSnapshot, _ = json.Marshal(map[string]any{"kind": "file", "name": in.FileLabel})
	} else {
		source, e := s.investigationSource(r.Context(), pg, investigationRequest{SourceID: in.SourceID, ExpectedSourceRevision: in.ExpectedSourceRevision})
		if e != nil {
			defensiveCaseError(w, e)
			return
		}
		credentials, e := s.securitySourceCredentials(source)
		if e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
		defer cancel()
		out.Collection, err = securitysource.FetchInvestigation(ctx, source.Config, credentials, in.Scope, in.Mapping, in.Sourcetypes, known)
		if err != nil {
			code := 502
			if errors.Is(err, investigation.ErrInvalid) || errors.Is(err, securitysource.ErrInvalid) {
				code = 400
			}
			writeErr(w, code, err.Error())
			return
		}
		out.SourceSnapshot, _ = json.Marshal(struct {
			*db.SecuritySource
			InvestigationSourcetypes []string `json:"investigation_sourcetypes"`
		}{source, in.Sourcetypes})
	}
	boundDefensiveCaseMarkers(&out.Collection, knownRuns)
	out.Mapping = out.Collection.Mapping
	saved, err := pg.SaveDefensiveCase(r.Context(), out)
	if err != nil {
		defensiveCaseError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, defensiveCasePreview(saved))
}

func boundDefensiveCaseMarkers(c *investigation.Collection, runs []db.InvestigationVerification) {
	originalWarnings := len(c.Warnings)
	boundInvestigationMarkers(c, runs)
	if len(c.Warnings) > originalWarnings && c.Stats.KnownARTEX > 0 {
		c.Warnings[len(c.Warnings)-1] = "ARTEX 구분은 전체 등록 검증 실행 ID와 실제 실행 시간 구간 일치에 근거합니다. 표식은 인증 수단이 아니므로 원본 요청·점검 일정과 대조하세요."
	}
}

func defensiveCasePreview(in *db.DefensiveCase) *db.DefensiveCase {
	out := *in
	out.Collection.Files = append([]investigation.FileEvidence{}, in.Collection.Files...)
	for i := range out.Collection.Files {
		out.Collection.Files[i].Content = ""
	}
	return &out
}

func (s *Server) readDefensiveCase(w http.ResponseWriter, r *http.Request) (*db.DefensiveCase, bool) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "사건 ID를 확인해 주세요")
		return nil, false
	}
	pg := s.pg(w)
	if pg == nil {
		return nil, false
	}
	out, err := pg.GetDefensiveCase(r.Context(), id)
	if err != nil {
		defensiveCaseError(w, err)
		return nil, false
	}
	return out, true
}
func (s *Server) getDefensiveCase(w http.ResponseWriter, r *http.Request) {
	out, ok := s.readDefensiveCase(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, defensiveCasePreview(out))
}
func (s *Server) deleteDefensiveCase(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "사건 ID를 확인해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := pg.DeleteDefensiveCase(r.Context(), id); err != nil {
		defensiveCaseError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"deleted": strconv.FormatInt(id, 10)})
}
func (s *Server) exportDefensiveCase(w http.ResponseWriter, r *http.Request) {
	out, ok := s.readDefensiveCase(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="defensive-case-%d.json"`, out.ID))
	writeJSON(w, 200, out)
}
