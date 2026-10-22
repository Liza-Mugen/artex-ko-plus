package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/offensivereview"
	"github.com/Autumn-27/norma/llm"
	"github.com/google/uuid"
)

type offensiveCheckpointProvider struct{}

func (offensiveCheckpointProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}
func (offensiveCheckpointProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	panic("tests use injected review function")
}

func offensiveCheckpointFixture(t *testing.T) (*Server, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("isolated ARTEX_PG_DSN required")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	s := &Server{m: &Manager{pg: pg}, ctx: ctx, jwtKey: []byte("offensive-checkpoint-test-signing-key")}
	rt := s.offensiveReviews()
	rt.provider = func(int64) (llm.Provider, agent.Config, bool) {
		return offensiveCheckpointProvider{}, agent.Config{}, true
	}
	t.Cleanup(func() {
		cancel()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			rt.mu.Lock()
			n := len(rt.jobs)
			rt.mu.Unlock()
			if n == 0 {
				pg.Close()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("candidate worker did not exit")
		pg.Close()
	})
	token, _ := signJWT(s.jwtKey)
	// Exercise the retained checkpoint engine directly. Its public start route
	// is retired and is independently covered by diagnostic route tests.
	handler := offensiveLegacyHandler(s)
	return s, func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
}

func offensiveCheckpointInput(kind string, n int) *preparedOffensiveReview {
	p := &preparedOffensiveReview{Kind: kind, EvidenceSHA256: "frozen-report", AutoResults: map[string]offensivereview.Result{}}
	for i := 0; i < n; i++ {
		id := string(rune('a' + i))
		p.Candidates = append(p.Candidates, offensivereview.Candidate{ID: id, Kind: kind, Title: "candidate " + id, Evidence: []offensivereview.Evidence{{Ref: "evidence:" + id, Text: "bounded source or response"}}})
	}
	return p
}
func offensiveCheckpointResult(c offensivereview.Candidate) (offensivereview.Result, offensivereview.Metrics, error) {
	return offensivereview.Result{CandidateID: c.ID, Status: "insufficient_evidence", Summary: "reviewed " + c.ID, EvidenceRefs: []string{c.Evidence[0].Ref}, Limitations: []string{"no dynamic proof"}}, offensivereview.Metrics{ModelCalls: 1, ModelElapsedMS: 7, Usage: llm.Usage{InputTokens: 30, OutputTokens: 12}}, nil
}
func awaitOffensiveCheckpoint(t *testing.T, s *Server, id, status string) *db.OffensiveReview {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r, err := s.m.pg.GetOffensiveReview(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if r != nil && r.Status == status {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	r, _ := s.m.pg.GetOffensiveReview(t.Context(), id)
	t.Fatalf("wanted %s got %+v", status, r)
	return nil
}
func checkpointPath(id string) string { return "/api/offensive/runs/" + id + "/candidate-review" }
func cleanupCheckpoint(t *testing.T, s *Server, id string) {
	t.Helper()
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM offensive_candidate_reviews WHERE run_id=$1`, id) })
}

func TestOffensiveCandidateReviewResumeAPIAndSource(t *testing.T) {
	for _, kind := range []string{"api", "source"} {
		t.Run(kind, func(t *testing.T) {
			s, request := offensiveCheckpointFixture(t)
			id := uuid.NewString()
			cleanupCheckpoint(t, s, id)
			rt := s.offensiveReviews()
			input := offensiveCheckpointInput(kind, 3)
			rt.prepare = func(context.Context, string) (*preparedOffensiveReview, error) { return input, nil }
			var mu sync.Mutex
			seen := map[string]int{}
			rt.review = func(ctx context.Context, p llm.Provider, c offensivereview.Candidate, max int) (offensivereview.Result, offensivereview.Metrics, error) {
				mu.Lock()
				seen[c.ID]++
				mu.Unlock()
				return offensiveCheckpointResult(c)
			}
			if w := request("GET", checkpointPath(id), ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"review":null`) {
				t.Fatal(w.Code, w.Body.String())
			}
			if w := request("POST", checkpointPath(id), `{"llm_profile_id":42,"batch_size":1}`); w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			first := awaitOffensiveCheckpoint(t, s, id, "partial")
			if first.Reviewed != 1 || first.Pending != 2 || first.Attempts[0].ModelCalls != 1 {
				t.Fatal(first)
			}
			if w := request("POST", checkpointPath(id), `{"batch_size":5}`); w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			last := awaitOffensiveCheckpoint(t, s, id, "completed")
			if last.Reviewed != 3 || len(last.Attempts) != 2 || last.Attempts[1].ProfileID != 42 || last.Attempts[1].ModelCalls != 2 {
				t.Fatal(last)
			}
			if w := request("POST", checkpointPath(id), `{}`); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			mu.Lock()
			defer mu.Unlock()
			for id, n := range seen {
				if n != 1 {
					t.Fatalf("candidate %s rerun %d", id, n)
				}
			}
		})
	}
}

func TestOffensiveCandidateReviewDuplicateCancelAndLateResult(t *testing.T) {
	s, request := offensiveCheckpointFixture(t)
	id := uuid.NewString()
	cleanupCheckpoint(t, s, id)
	rt := s.offensiveReviews()
	input := offensiveCheckpointInput("api", 2)
	rt.prepare = func(context.Context, string) (*preparedOffensiveReview, error) { return input, nil }
	entered := make(chan struct{})
	release := make(chan struct{})
	var firstCall atomic.Bool
	rt.review = func(ctx context.Context, p llm.Provider, c offensivereview.Candidate, max int) (offensivereview.Result, offensivereview.Metrics, error) {
		if firstCall.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return offensiveCheckpointResult(c)
	}
	if w := request("POST", checkpointPath(id), `{"llm_profile_id":42}`); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	<-entered
	if w := request("POST", checkpointPath(id), `{"llm_profile_id":42}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("POST", checkpointPath(id)+"/cancel", `{}`); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	close(release)
	r := awaitOffensiveCheckpoint(t, s, id, "cancelled")
	time.Sleep(20 * time.Millisecond)
	r, _ = s.m.pg.GetOffensiveReview(t.Context(), id)
	if r.Reviewed != 0 || len(r.Attempts) != 1 || r.Attempts[0].ModelCalls != 1 || r.Candidates[0].Status != "pending" || !strings.Contains(r.Reason, "토큰 사용량은 확인되지") {
		t.Fatal("late result overwrote cancellation", r)
	}
	if w := request("POST", checkpointPath(id), `{"batch_size":5}`); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	awaitOffensiveCheckpoint(t, s, id, "completed")
}

func TestOffensiveCandidateReviewQueueTimeoutAndAutomaticAuth(t *testing.T) {
	s, request := offensiveCheckpointFixture(t)
	apiID, sourceID := uuid.NewString(), uuid.NewString()
	cleanupCheckpoint(t, s, apiID)
	cleanupCheckpoint(t, s, sourceID)
	rt := s.offensiveReviews()
	api, source := offensiveCheckpointInput("api", 3), offensiveCheckpointInput("source", 1)
	api.AutoResults["b"] = offensivereview.Result{CandidateID: "b", Status: "auth_required", Summary: "401 evidence", EvidenceRefs: []string{"evidence:b"}}
	rt.prepare = func(_ context.Context, id string) (*preparedOffensiveReview, error) {
		if id == apiID {
			return api, nil
		}
		return source, nil
	}
	rt.candidateTimeout = 500 * time.Millisecond
	var active, maxActive atomic.Int32
	var failAPI atomic.Bool
	failAPI.Store(true)
	rt.review = func(ctx context.Context, p llm.Provider, c offensivereview.Candidate, max int) (offensivereview.Result, offensivereview.Metrics, error) {
		n := active.Add(1)
		defer active.Add(-1)
		if n > maxActive.Load() {
			maxActive.Store(n)
		}
		if c.Kind == "api" && failAPI.Load() {
			<-ctx.Done()
			return offensivereview.Result{}, offensivereview.Metrics{ModelCalls: 1}, ctx.Err()
		}
		return offensiveCheckpointResult(c)
	}
	if w := request("POST", checkpointPath(apiID), `{"llm_profile_id":42}`); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	awaitOffensiveCheckpoint(t, s, apiID, "running")
	if w := request("POST", checkpointPath(sourceID), `{"llm_profile_id":42}`); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	queued := awaitOffensiveCheckpoint(t, s, sourceID, "queued")
	if queued.Attempts[0].StartedAt != nil {
		t.Fatal("queue consumed active budget")
	}
	first := awaitOffensiveCheckpoint(t, s, apiID, "partial")
	second := awaitOffensiveCheckpoint(t, s, sourceID, "completed")
	if first.Reviewed != 1 || first.Candidates[0].Status != "error" || first.Candidates[1].Status != "auth_required" || first.Candidates[2].Status != "pending" || first.Attempts[0].ModelCalls != 1 || second.Attempts[0].QueueWaitMS <= 0 || maxActive.Load() != 1 {
		t.Fatal("bad serialized outcomes", first, second, maxActive.Load())
	}
	// One-candidate continuation processes the untouched candidate before
	// retrying the timed-out one, preventing retry starvation.
	failAPI.Store(false)
	if w := request("POST", checkpointPath(apiID), `{"batch_size":1}`); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	resumed := awaitOffensiveCheckpoint(t, s, apiID, "partial")
	if resumed.Reviewed != 2 || resumed.Candidates[2].Result == nil || resumed.Candidates[0].Result != nil {
		t.Fatal("pending candidate was starved by an error retry", resumed)
	}
	if w := request("GET", checkpointPath(apiID), ""); w.Code != 200 {
		t.Fatal(w.Code)
	} else {
		var v map[string]json.RawMessage
		if json.Unmarshal(w.Body.Bytes(), &v) != nil || v["review"] == nil {
			t.Fatal("missing review")
		}
	}
}

func TestOffensiveCandidateReviewValidationAndAuthentication(t *testing.T) {
	s, request := offensiveCheckpointFixture(t)
	id := uuid.NewString()
	rt := s.offensiveReviews()
	var preparations atomic.Int32
	rt.prepare = func(context.Context, string) (*preparedOffensiveReview, error) {
		preparations.Add(1)
		return offensiveCheckpointInput("api", 1), nil
	}
	for _, body := range []string{`{"batch_size":6}`, `{"batch_size":-1}`, `{"llm_profile_id":-1}`, `{"url":"https://elsewhere.invalid"}`} {
		if w := request("POST", checkpointPath(id), body); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if preparations.Load() != 0 {
		t.Fatal("invalid input accessed runner")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", checkpointPath(id), strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated review", w.Code)
	}
}

func TestOffensiveCandidateReviewErrorsAreSafeAndActionable(t *testing.T) {
	if got := offensiveReviewError(offensivereview.ErrRateLimited); got != offensivereview.ErrRateLimited.Error() {
		t.Fatal("lost rate-limit guidance", got)
	}
	if got := offensiveReviewError(errors.New("private-provider-key-in-error")); strings.Contains(got, "private-provider-key") {
		t.Fatal("provider credentials leaked")
	}
	if got := offensiveReviewError(context.DeadlineExceeded); !strings.Contains(got, "300초") {
		t.Fatal("missing bounded candidate deadline", got)
	}
}
