package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/closedloop"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
)

func (s *Server) registerClosedLoopLive(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/closed-loop/live-cycles", s.listClosedLoopLive)
	mux.HandleFunc("POST /api/closed-loop/live-cycles", s.createClosedLoopLive)
	mux.HandleFunc("GET /api/closed-loop/live-cycles/{id}", s.getClosedLoopLive)
	mux.HandleFunc("GET /api/closed-loop/live-cycles/{id}/export", s.exportClosedLoopLive)
	mux.HandleFunc("POST /api/closed-loop/live-cycles/{id}/collect", s.collectClosedLoopLive)
	mux.HandleFunc("POST /api/closed-loop/live-cycles/{id}/suggest", s.suggestClosedLoopLive)
	mux.HandleFunc("PUT /api/closed-loop/live-cycles/{id}/candidate", s.candidateClosedLoopLive)
	mux.HandleFunc("POST /api/closed-loop/live-cycles/{id}/rerun", s.rerunClosedLoopLive)
	mux.HandleFunc("POST /api/closed-loop/live-cycles/{id}/stop", s.stopClosedLoopLive)
}
func liveCycleID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	w.Header().Set("Cache-Control", "no-store")
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "올바른 Closed-loop 실행 ID를 입력하세요")
		return 0, false
	}
	return id, true
}
func writeLiveLoopError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrClosedLoopLiveConflict), errors.Is(err, db.ErrDefenseConflict):
		writeErr(w, 409, err.Error())
	case errors.Is(err, db.ErrDefenseInvalid), errors.Is(err, closedloop.ErrInvalid), errors.Is(err, securitysource.ErrInvalid):
		writeErr(w, 400, err.Error())
	case errors.Is(err, db.ErrClosedLoopNotFound), errors.Is(err, db.ErrDefenseExecutionNotFound):
		writeErr(w, 404, err.Error())
	default:
		writeClosedLoopError(w, err)
	}
}
func (s *Server) listClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	pg := s.pg(w)
	if pg == nil {
		return
	}
	items, err := pg.ListClosedLoopLiveCycles(r.Context())
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"cycles": items})
}
func (s *Server) createClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in db.ClosedLoopLiveInput
	if !decodePurpleRequestLimit(w, r, &in, 256<<10) {
		return
	}
	pg := s.pg(w)
	if pg == nil || !s.findingRetestReady(w, r, pg, in.FindingID) {
		return
	}
	c, retest, conv, execution, created, err := pg.CreateClosedLoopLiveCycle(r.Context(), in)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	if created {
		s.dispatchFindingRetest(retest, conv)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"cycle": c, "retest": retest, "execution": execution, "created": created})
}
func (s *Server) getClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	id, ok := liveCycleID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	c, err := pg.GetClosedLoopLiveCycle(r.Context(), id, false)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) exportClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	id, ok := liveCycleID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	c, err := pg.GetClosedLoopLiveCycle(r.Context(), id, true)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="closed-loop-live-%d.json"`, id))
	writeJSON(w, 200, c)
}
func (s *Server) candidateClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	id, ok := liveCycleID(w, r)
	if !ok {
		return
	}
	var in struct {
		ExpectedRevision int64           `json:"expected_revision"`
		Rule             closedloop.Rule `json:"rule"`
		Note             string          `json:"note"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 256<<10) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	c, err := pg.SetClosedLoopLiveCandidate(r.Context(), id, in.ExpectedRevision, in.Rule, in.Note)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) suggestClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	id, ok := liveCycleID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.SuggestClosedLoopLiveCandidate(r.Context(), id)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) rerunClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	id, ok := liveCycleID(w, r)
	if !ok {
		return
	}
	var in struct {
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decodePurpleRequest(w, r, &in) {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	c, err := pg.GetClosedLoopLiveCycle(r.Context(), id, false)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	if !s.findingRetestReady(w, r, pg, c.FindingID) {
		return
	}
	out, retest, conv, execution, created, err := pg.RerunClosedLoopLiveCycle(r.Context(), id, in.ExpectedRevision)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	if created {
		s.dispatchFindingRetest(retest, conv)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"cycle": out, "retest": retest, "execution": execution, "created": created})
}
func (s *Server) stopClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	id, ok := liveCycleID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	c, conv, err := pg.StopClosedLoopLiveCycle(r.Context(), id)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	if conv != nil {
		s.cancelConversation(*conv)
	}
	writeJSON(w, 200, c)
}

// This is the actual evidence path: a finished fresh ARTEX execution, a pinned
// read-only source and bounded native audit/alert + structured shadow queries.
// File mode consumes only the existing independently validated upload endpoint.
func (s *Server) collectClosedLoopLive(w http.ResponseWriter, r *http.Request) {
	id, ok := liveCycleID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	c, err := pg.GetClosedLoopLiveCycle(r.Context(), id, false)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	if c.Status == "stopped" {
		writeLiveLoopError(w, db.ErrClosedLoopLiveConflict)
		return
	}
	execution := c.Baseline
	candidate := c.BaselineRule
	if c.Current != nil {
		execution = c.Current
		if c.CandidateRule == nil {
			writeLiveLoopError(w, db.ErrClosedLoopLiveConflict)
			return
		}
		candidate = *c.CandidateRule
	}
	if execution.State != "current" {
		writeLiveLoopError(w, db.ErrClosedLoopLiveConflict)
		return
	}
	q, complete, err := defenseExecutionWindow(execution, time.Now().UTC())
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	if !complete {
		writeErr(w, 409, "실제 실행 종료 후 60초의 관측 기간이 끝난 뒤 수집해 주세요")
		return
	}
	scope := investigation.Scope{Target: c.LogTarget, PathPrefix: c.LogPath, Start: q.Start, End: q.End}
	var native *db.DefenseAssessment
	var shadow *securitysource.ClosedLoopSearchResult
	if execution.SourceKind == "file" {
		native, err = pg.GetLatestClosedLoopNativeAssessment(r.Context(), c.FindingID, execution.ID)
		if err != nil {
			writeErr(w, 409, "이 실행의 감사·경보 파일을 먼저 업로드하세요")
			return
		}
		var snapshot struct {
			Config securitysource.FileConfig `json:"config"`
		}
		if err = json.Unmarshal(execution.SourceSnapshot, &snapshot); err != nil {
			writeLiveLoopError(w, err)
			return
		}
		// Uploaded evidence carries its own verified original bounds; do not relabel
		// an old file as a fresh execution or expand an incomplete upload's bounds.
		q.Start, q.End = native.Evidence.WindowStart, native.Evidence.WindowEnd
		scope.Start, scope.End = q.Start, q.End
		shadow, err = securitysource.EvaluateClosedLoopFile(securitysource.Config{CorrelationField: snapshot.Config.CorrelationField}, q, scope, c.LogMapping, c.BaselineRule, candidate, native.Evidence)
		if shadow == nil {
			writeErr(w, 400, "업로드 원본·실행 ID·필드 매핑을 확인하세요")
			return
		}
	} else {
		source, loadErr := pg.GetSecuritySource(r.Context(), execution.SourceID)
		if loadErr != nil {
			writeLiveLoopError(w, db.ErrClosedLoopLiveConflict)
			return
		}
		var snapshot db.SecuritySource
		if json.Unmarshal(execution.SourceSnapshot, &snapshot) != nil || snapshot.ID != source.ID || snapshot.Revision != source.Revision || !securitysource.EqualConfig(snapshot.Config, source.Config) || !source.Enabled {
			writeLiveLoopError(w, db.ErrClosedLoopLiveConflict)
			return
		}
		auth, authErr := s.securitySourceCredentials(source)
		if authErr != nil {
			writeErr(w, 409, "저장된 보안 로그 인증 정보를 확인하세요")
			return
		}
		select {
		case defenseCollectSlots <- struct{}{}:
			defer func() { <-defenseCollectSlots }()
		default:
			writeErr(w, 429, "다른 증거 수집이 진행 중입니다. 잠시 후 다시 시도하세요")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		evidence, fetchErr := securitysource.Fetch(ctx, source.Config, auth, q)
		if fetchErr != nil {
			evidence = &securitysource.Evidence{Complete: false, CollectedAt: time.Now().UTC(), WindowStart: q.Start, WindowEnd: q.End, Warnings: []string{"실제 감사·경보 검색이 실패했습니다. 수집 근거가 부족합니다"}, Events: []securitysource.Event{}}
		}
		native, err = pg.SaveDefenseAssessment(ctx, c.FindingID, execution.ID, evidence)
		if err != nil {
			writeLiveLoopError(w, err)
			return
		}
		shadow, err = securitysource.FetchClosedLoopRules(ctx, source.Config, auth, q, scope, c.LogMapping, c.BaselineRule, candidate)
		if shadow == nil {
			writeErr(w, 502, "구조화된 규칙 평가 검색을 시작하지 못했습니다. 원본 필드 매핑을 확인하세요")
			return
		}
	}
	// Adapter returns partial sanitized result along with an error. Preserve that
	// attempt and its unknown verdict instead of turning absence into a success.
	if err != nil {
		shadow.Complete = false
		if shadow.ErrorCode == "" {
			shadow.ErrorCode = "evaluation_failed"
		}
	}
	out, err := pg.SaveClosedLoopLiveObservation(r.Context(), id, execution.ID, c.Revision, native, shadow)
	if err != nil {
		writeLiveLoopError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
