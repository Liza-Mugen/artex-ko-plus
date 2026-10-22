package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

func defensiveDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN is required for isolated PostgreSQL integration tests")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}
func defensiveCaseInput(t *testing.T) DefensiveCase {
	t.Helper()
	scope := investigation.Scope{Target: "app.example", Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Add(-time.Minute)}
	mapping := investigation.DefaultMapping()
	collection, err := investigation.ParseFiles([]investigation.InputFile{{Name: "source.jsonl", Content: fmt.Sprintf(`{"timestamp":%q,"id":"standalone-event","target":"app.example","path":"/login","event_kind":"alert"}`, scope.Start.Add(time.Minute).Format(time.RFC3339Nano))}}, scope, mapping, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return DefensiveCase{Title: "Standalone log case", Question: "이 경보의 근거를 확인하세요.", SourceKind: "file", SourceSnapshot: json.RawMessage(`{"kind":"file","name":"original logs"}`), Scope: scope, Mapping: mapping, Collection: collection}
}
func saveDefensiveCaseForTest(t *testing.T, d *DB) *DefensiveCase {
	t.Helper()
	c, err := d.SaveDefensiveCase(t.Context(), defensiveCaseInput(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM defensive_cases WHERE id=$1`, c.ID) })
	return c
}
func TestDefensiveCaseNoFindingIndependentSnapshot(t *testing.T) {
	d := defensiveDB(t)
	var before, after int
	if err := d.QueryRow(`SELECT count(*) FROM findings`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	in := defensiveCaseInput(t)
	in.Analysis.Summary = "client verdict must not be trusted"
	c, err := d.SaveDefensiveCase(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM defensive_cases WHERE id=$1`, c.ID) })
	if err = d.QueryRow(`SELECT count(*) FROM findings`).Scan(&after); err != nil || before != after {
		t.Fatal("created a synthesized finding", err)
	}
	if c.FindingID != 0 || c.FindingSnapshot != nil || c.Plan.Family != "defensive" || c.Analysis.ObservedCount != 1 || c.Analysis.Summary == in.Analysis.Summary {
		t.Fatalf("case %+v", c)
	}
	restored, err := d.GetDefensiveCase(t.Context(), c.ID)
	if err != nil || restored.Collection.Files[0].Content != in.Collection.Files[0].Content {
		t.Fatal("original evidence changed", err)
	}
	list, err := d.ListDefensiveCases(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "standalone-event") || strings.Contains(string(raw), "finding_snapshot") {
		t.Fatal("list leaked original evidence")
	}
	if _, err = d.GetDefensiveCase(t.Context(), c.ID+99999999); !errors.Is(err, ErrDefensiveCaseNotFound) {
		t.Fatal("missing case accepted", err)
	}
}
func TestDefensiveCaseDeleteBlocksActiveRunAndCascadesStoppedRuns(t *testing.T) {
	d := defensiveDB(t)
	c := saveDefensiveCaseForTest(t, d)
	run, created, err := d.CreateDefensiveCaseRun(t.Context(), c.ID, json.RawMessage(`{}`))
	if err != nil || !created {
		t.Fatal("create run", err)
	}
	if err = d.DeleteDefensiveCase(t.Context(), c.ID); !errors.Is(err, ErrDefensiveCaseActive) {
		t.Fatal("active case was deleted", err)
	}
	if _, err = d.GetDefensiveCase(t.Context(), c.ID); err != nil {
		t.Fatal("active case lost", err)
	}
	if _, err = d.CancelDefensiveCaseRun(t.Context(), c.ID, run.ID); err != nil {
		t.Fatal("cancel run", err)
	}
	if err = d.DeleteDefensiveCase(t.Context(), c.ID); err != nil {
		t.Fatal("delete stopped case", err)
	}
	if _, err = d.GetDefensiveCase(t.Context(), c.ID); !errors.Is(err, ErrDefensiveCaseNotFound) {
		t.Fatal("deleted case remained", err)
	}
	if _, err = d.GetDefensiveCaseRun(t.Context(), c.ID, run.ID); !errors.Is(err, ErrDefensiveCaseRunNotFound) {
		t.Fatal("case-owned run remained", err)
	}
	if err = d.DeleteDefensiveCase(t.Context(), c.ID); !errors.Is(err, ErrDefensiveCaseNotFound) {
		t.Fatal("repeated deletion was accepted", err)
	}
}
func TestDefensiveCaseOptionalFindingSurvivesDelete(t *testing.T) {
	d, id := purpleDB(t)
	overview, err := d.GetInvestigationOverview(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	in := defensiveCaseInput(t)
	in.FindingID = id
	in.EvidenceVersion = overview.EvidenceVersion
	in.SourceFingerprint = overview.SourceFingerprint
	c, err := d.SaveDefensiveCase(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM defensive_cases WHERE id=$1`, c.ID) })
	if c.FindingSnapshot == nil || c.FindingSnapshot.Evidence != "source evidence" {
		t.Fatal("optional finding snapshot missing")
	}
	if _, err = d.Exec(`UPDATE findings SET evidence='changed after snapshot' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SaveDefensiveCase(t.Context(), in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatal("stale finding snapshot accepted", err)
	}
	if _, err = d.DeleteFinding(id); err != nil {
		t.Fatal(err)
	}
	restored, err := d.GetDefensiveCase(t.Context(), c.ID)
	if err != nil || restored.FindingSnapshot == nil || restored.FindingSnapshot.Evidence != "source evidence" {
		t.Fatal("case depended on finding lifecycle", err)
	}
	if _, created, err := d.CreateDefensiveCaseRun(t.Context(), c.ID, json.RawMessage(`{}`)); err != nil || !created {
		t.Fatal("snapshot cannot be investigated after finding removal", err)
	}
}
func TestDefensiveCaseRunConcurrentCancelRecoveryAndUsage(t *testing.T) {
	d := defensiveDB(t)
	c := saveDefensiveCaseForTest(t, d)
	const count = 6
	var wg sync.WaitGroup
	results := make(chan *DefensiveCaseRun, count)
	errs := make(chan error, count)
	for range count {
		wg.Go(func() {
			run, _, err := d.CreateDefensiveCaseRun(t.Context(), c.ID, json.RawMessage(`{"source_kind":"file"}`))
			if err != nil {
				errs <- err
			} else {
				results <- run
			}
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var id int64
	for run := range results {
		if id == 0 {
			id = run.ID
		}
		if run.ID != id {
			t.Fatal("duplicate queued work")
		}
	}
	started, err := d.StartDefensiveCaseRun(t.Context(), id)
	if err != nil || !started {
		t.Fatal(err)
	}
	usage := InvestigationRunUsage{ModelCalls: 2, Queries: 1, Rounds: 1, InputTokens: 30}
	if _, err = d.AppendDefensiveCaseRunEvent(t.Context(), id, "evidence", json.RawMessage(`{"ref":"kept-evidence"}`), usage); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AppendDefensiveCaseRunEvent(t.Context(), id, "bad", json.RawMessage(`{}`), InvestigationRunUsage{}); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatal("budget counters erased", err)
	}
	cancelled, err := d.CancelDefensiveCaseRun(t.Context(), c.ID, id)
	if err != nil || cancelled.Status != "cancelled" || len(cancelled.Events) != 1 {
		t.Fatal("cancel evidence lost", err)
	}
	if changed, err := d.FinishDefensiveCaseRun(t.Context(), id, "completed", json.RawMessage(`{"summary":"late"}`), "", usage); err != nil || changed {
		t.Fatal("late worker overwrote cancellation", err)
	}
	fresh, created, err := d.CreateDefensiveCaseRun(t.Context(), c.ID, json.RawMessage(`{}`))
	if err != nil || !created || fresh.ID == id {
		t.Fatal("new run after stop failed", err)
	}
	if _, err = d.RecoverDefensiveCaseRuns(t.Context()); err != nil {
		t.Fatal(err)
	}
	interrupted, err := d.GetDefensiveCaseRun(t.Context(), c.ID, fresh.ID)
	if err != nil || interrupted.Status != "interrupted" {
		t.Fatal("restart recovery failed", err)
	}
	if _, err = d.GetDefensiveCaseRun(t.Context(), c.ID+1, id); !errors.Is(err, ErrDefensiveCaseRunNotFound) {
		t.Fatal("cross-case run exposed", err)
	}
}

func TestDefensiveCaseRegisteredVerificationWindowsAcrossFindings(t *testing.T) {
	d, id := purpleDB(t)
	if _, err := d.SaveDefensePlan(t.Context(), id, purplePlan()); err != nil {
		t.Fatal(err)
	}
	execution := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, id, fileExecutionInput(t, d, id)))
	scope := defensiveCaseInput(t).Scope
	runs, err := d.KnownDefensiveVerifications(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, run := range runs {
		if run.ID == execution.CorrelationID {
			found = true
			if !run.Start.Equal(execution.Retest.StartedAt.Add(-30*time.Second)) || !run.End.Equal(execution.Retest.FinishedAt.Add(time.Minute)) {
				t.Fatal("registered execution window lost")
			}
		}
	}
	if !found {
		t.Fatal("standalone case omitted another finding's verification")
	}
	// Archived/deleted conversations cannot remove an already recorded test window.
	if _, err = d.Exec(`DELETE FROM finding_retests WHERE id=$1`, execution.RetestID); err != nil {
		t.Fatal(err)
	}
	cached, err := d.KnownDefensiveVerifications(t.Context(), scope)
	if err != nil || len(cached) != len(runs) {
		t.Fatal("cached verification snapshot lost", err)
	}
	scope.Start = time.Now().UTC().Add(-24 * time.Hour)
	scope.End = scope.Start.Add(time.Minute)
	outside, err := d.KnownDefensiveVerifications(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range outside {
		if run.ID == execution.CorrelationID {
			t.Fatal("unrelated execution window leaked into known markers")
		}
	}
}
