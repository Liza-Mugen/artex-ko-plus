package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

func investigationFixture(t *testing.T, d *DB, id int64) FindingInvestigation {
	t.Helper()
	ctx := t.Context()
	overview, err := d.GetInvestigationOverview(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	scope := investigation.Scope{Target: "app.example", PathPrefix: "/ftp", Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Add(-time.Minute)}
	raw := fmt.Sprintf(`{"timestamp":%q,"id":"prior-request","target":"app.example","path":"/ftp/file.txt","status":200}`, scope.Start.Add(time.Minute).Format(time.RFC3339Nano))
	collection, err := investigation.ParseFiles([]investigation.InputFile{{Name: "historical.jsonl", Content: raw}}, scope, investigation.DefaultMapping(), true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return FindingInvestigation{Title: "Historical investigation", SourceKind: "file", SourceSnapshot: json.RawMessage(`{"name":"test only"}`), Scope: scope, Mapping: investigation.DefaultMapping(), Collection: collection, EvidenceVersion: overview.EvidenceVersion, SourceFingerprint: overview.SourceFingerprint}
}

func TestInvestigationOverviewUsesStoredDefenseGuidance(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	if _, err := d.ExecContext(ctx, `UPDATE findings SET name='비정상 JSON 오류 페이지 정보 노출',vulnclass='CWE-209: Information Exposure Through an Error Message',summary='POST /api/ai/chat/anonymous 요청에서 기본 500 오류 페이지 노출' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	initial, err := d.GetInvestigationOverview(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if initial.RecommendedPath != "/api/ai/chat/anonymous" {
		t.Fatalf("finding path was not recommended: %q", initial.RecommendedPath)
	}
	input, err := d.GetDefenseScenarioInput(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	draft := DefenseScenario{Title: "비정상 JSON 오류 응답 가정", Stages: []DefenseScenarioStage{{ID: "stage-1", Title: "500 응답과 서버 배너 확인"}}}
	if _, err := d.SaveDefenseScenario(ctx, id, input, draft); err != nil {
		t.Fatal(err)
	}
	withScenario, err := d.GetInvestigationOverview(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if withScenario.SourceFingerprint != initial.SourceFingerprint || len(withScenario.Plan.ScenarioAssumptions) == 0 {
		t.Fatalf("stored scenario was not used without changing investigation freshness: %+v", withScenario.Plan)
	}

	defenseInput := defenseRetestInput(t, d, id)
	r, c, _, created, err := d.CreateFindingRetestWithDefense(ctx, id, "isolated fixture", defenseInput)
	if err != nil || !created {
		t.Fatalf("create defense retest: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteConversation(c.ID) })
	if ok, err := d.StartFindingRetest(ctx, r.ID); err != nil || !ok {
		t.Fatalf("start defense retest: %t %v", ok, err)
	}
	if err := d.RecordFindingRetestResult(ctx, c.ID, "reproduced", "비정상 JSON 요청에서 오류 페이지 재현", "해당 실행에서 HTTP 500 응답 확인"); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishFindingRetest(r.ID, "completed", ""); err != nil {
		t.Fatal(err)
	}
	withRetest, err := d.GetInvestigationOverview(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if withRetest.SourceFingerprint != initial.SourceFingerprint || len(withRetest.Plan.VerifiedFacts) == 0 {
		t.Fatalf("completed defense retest was not used as historical fact: %+v", withRetest.Plan)
	}
	if _, err := d.ExecContext(ctx, `UPDATE findings SET evidence='changed source evidence' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	stale, err := d.GetInvestigationOverview(ctx, id)
	if err != nil || len(stale.Plan.ContextWarnings) == 0 {
		t.Fatalf("stale defense context was not identified: %+v %v", stale.Plan, err)
	}
}

func TestInvestigationHistoryPreservesRawAndRejectsStaleFinding(t *testing.T) {
	d, id := purpleDB(t)
	in := investigationFixture(t, d, id)
	saved, err := d.SaveFindingInvestigation(t.Context(), id, in)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID <= 0 || saved.State != "current" || saved.Analysis.ObservedCount != 1 {
		t.Fatalf("saved: %+v", saved)
	}
	if len(saved.Collection.Files) != 1 || saved.Collection.Files[0].Content != in.Collection.Files[0].Content {
		t.Fatal("original bytes changed")
	}
	overview, err := d.GetInvestigationOverview(t.Context(), id)
	if err != nil || len(overview.Investigations) != 1 {
		t.Fatalf("history: %+v %v", overview, err)
	}
	raw, _ := json.Marshal(overview)
	if strings.Contains(string(raw), "prior-request") {
		t.Fatal("history leaked raw events")
	}
	if _, err = d.Exec(`UPDATE findings SET evidence='new source evidence' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SaveFindingInvestigation(t.Context(), id, in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("stale accepted: %v", err)
	}
	restored, err := d.GetFindingInvestigation(t.Context(), id, saved.ID)
	if err != nil || restored.State != "stale" || restored.FindingSnapshot.Evidence != "source evidence" {
		t.Fatalf("historical snapshot mutated: %+v %v", restored, err)
	}
	if _, err = d.GetFindingInvestigation(t.Context(), id+999999, saved.ID); !errors.Is(err, ErrInvestigationNotFound) {
		t.Fatal("cross-finding record accepted", err)
	}
}
func TestInvestigationArchiveRoundTripAndBarrier(t *testing.T) {
	d, _ := purpleDB(t)
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("investigation archive fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); d.DeleteTask(task.ID) })
	finding, err := d.Exploration(task.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "investigation archive", Severity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	id := finding.FindingID
	in := investigationFixture(t, d, id)
	before, err := d.SaveFindingInvestigation(t.Context(), id, in)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.SaveFindingInvestigation(t.Context(), id, in); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatal("write crossed archive barrier", err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataCounts["finding_investigations"] != 1 {
		t.Fatal("missing investigation from archive")
	}
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/investigation-test-only.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	after, err := d.GetFindingInvestigation(t.Context(), id, before.ID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("investigation changed across archive restore")
	}
}
