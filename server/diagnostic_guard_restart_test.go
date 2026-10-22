package server

import (
	"strconv"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/google/uuid"
)

func TestDiagnosticGuardRestoresCodeOwnedScope(t *testing.T) {
	m := diagnosticManagerFixture(t)
	task, err := m.CreateTaskWithOptions(diagnosticMarker(uuid.NewString())+" restore fixture", "read-only goal", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{DeleteAssets: true, DeleteFindings: true}) })
	if !task.Guard.DiagnosticEnabled() || task.Guard.UseDiagnosticRequest("GET", "http://lab.local/api") == nil {
		t.Fatal("new diagnostic task did not start fail-closed")
	}
	constraintID, err := task.Store.AddConstraint("allow", `허용된 URL 접두 범위는 ["http://lab.local/api"]뿐입니다. 다른 호스트·포트·경로로 확장하지 마세요.`, "diagnostic-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	task.refreshDiagnosticScope()
	if !task.Guard.DiagnosticScopeReady() {
		t.Fatal("bootstrap scope was not activated before task execution")
	}
	if err := task.Guard.UseDiagnosticRequest("HEAD", "http://lab.local/api/ping"); err != nil {
		t.Fatal(err)
	}
	task.Guard.FinishDiagnosticRequest()
	task.refreshDiagnosticScope()
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	row, err := m.pg.GetTask(id)
	if err != nil {
		t.Fatal(err)
	}
	restored := taskFromPG(row, task.Store, m.interceptor)
	if err := restored.Guard.UseDiagnosticRequest("GET", "http://lab.local/api/items"); err != nil {
		t.Fatalf("saved scope not restored: %v", err)
	}
	restored.Guard.FinishDiagnosticRequest()
	if err := restored.Guard.UseDiagnosticRequest("GET", "http://outside.local/"); err == nil {
		t.Fatal("restored guard allowed scope escape")
	}
	if err := task.Store.UpdateConstraint(constraintID, "allow", `허용된 URL 접두 범위는 ["http://outside.local/"]뿐입니다. 다른 호스트·포트·경로로 확장하지 마세요.`); err == nil {
		t.Fatal("code-created scope constraint was editable")
	}
	if err := task.Store.DeleteConstraint(constraintID); err == nil {
		t.Fatal("code-created scope constraint was deletable")
	}
}
