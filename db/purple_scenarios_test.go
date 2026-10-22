package db

import (
	"errors"
	"strings"
	"testing"
)

func TestDefenseScenarioPersistenceCacheAndStaleness(t *testing.T) {
	d, findingID := purpleDB(t)
	ctx := t.Context()
	input, err := d.GetDefenseScenarioInput(ctx, findingID)
	if err != nil || len(input.SourceFingerprint) != 32 || len(input.SourceConfigFingerprint) != 64 {
		t.Fatalf("input: %+v %v", input, err)
	}
	initial, err := d.GetFindingDefense(ctx, findingID)
	if err != nil || initial.Scenario != nil {
		t.Fatalf("GET generated a scenario: %+v %v", initial, err)
	}
	plan := purplePlan()
	before, err := d.SaveDefensePlan(ctx, findingID, plan)
	if err != nil {
		t.Fatal(err)
	}
	draft := DefenseScenario{Title: "가정된 요청 흐름", AttackSteps: []DefenseAttackStep{{ID: "step-1", Description: "허가된 진단 요청", Basis: "hypothetical", Evidence: "보고된 취약점"}},
		Stages: []DefenseScenarioStage{{ID: "stage-1", AttackStepID: "step-1", Title: "HTTP 경계", Equipment: []DefenseEquipment{{Kind: "WAF", Presence: "unknown", Basis: "근거 없음"}},
			LogSources: []string{"HTTP 요청 로그"}, RequiredFields: []string{"path"}, SplunkSources: []DefenseSplunkSource{{ID: 999, Name: "irrelevant-connection"}},
			RuleDraft: DefenseRuleDraft{Format: "spl", Query: "index=<index> | stats count by path", Rationale: "동일 경로 요청"},
			BenignBaseline: "정상 요청", SuccessCriteria: "실제 로그와 대조", Limitations: []string{"로그 연동 미확인"}}}}
	state, err := d.SaveDefenseScenario(ctx, findingID, input, draft)
	if err != nil || state.Scenario == nil || state.Scenario.State != "current" || state.Scenario.ID <= 0 || state.Plan == nil || state.Plan.Revision != before.Plan.Revision {
		t.Fatalf("save scenario: %+v %v", state, err)
	}
	var stored string
	if err := d.QueryRowContext(ctx, `SELECT payload::text FROM finding_defense_scenarios WHERE finding_id=$1`, findingID).Scan(&stored); err != nil || strings.Contains(stored, "irrelevant-connection") {
		t.Fatalf("new scenario stored connection candidates: %s %v", stored, err)
	}
	if _, err := d.ExecContext(ctx, `UPDATE finding_defense_scenarios SET payload=jsonb_set(payload,'{stages,0,splunk_sources}',
		'[{"id":"999","name":"legacy-candidate","index":"old","audit_sourcetype":"old","alert_sourcetype":"old","status":"configured_unverified"}]'::jsonb)
		WHERE finding_id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	legacy, err := d.GetFindingDefense(ctx, findingID)
	if err != nil || legacy.Scenario == nil || len(legacy.Scenario.Stages[0].SplunkSources) != 0 {
		t.Fatalf("legacy connection candidates leaked from scenario read: %+v %v", legacy, err)
	}
	again, err := d.SaveDefenseScenario(ctx, findingID, input, draft)
	if err != nil || again.Scenario == nil || again.Scenario.ID != state.Scenario.ID || !again.Scenario.CreatedAt.Equal(state.Scenario.CreatedAt) {
		t.Fatalf("duplicate changed cached scenario: %+v %v", again, err)
	}
	if _, err := d.ExecContext(ctx, `UPDATE findings SET summary='new diagnosis evidence' WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	stale, err := d.GetFindingDefense(ctx, findingID)
	if err != nil || stale.Scenario == nil || stale.Scenario.State != "stale" {
		t.Fatalf("edited finding must stale scenario: %+v %v", stale, err)
	}
	if _, err := d.SaveDefenseScenario(ctx, findingID, input, draft); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("old evidence snapshot accepted: %v", err)
	}
	updatedInput, err := d.GetDefenseScenarioInput(ctx, findingID)
	if err != nil || updatedInput.SourceFingerprint == input.SourceFingerprint {
		t.Fatalf("new input fingerprint: %+v %v", updatedInput, err)
	}
	regenerated, err := d.SaveDefenseScenario(ctx, findingID, updatedInput, draft)
	if err != nil || regenerated.Scenario == nil || regenerated.Scenario.State != "current" || regenerated.Plan.Revision != before.Plan.Revision {
		t.Fatalf("regenerate without plan mutation: %+v %v", regenerated, err)
	}
	var sourceID int64
	if err := d.QueryRowContext(ctx, `INSERT INTO security_sources(name,config,enabled)
		VALUES('scenario-test-source','{"index":"unit_security","audit_sourcetype":"unit:audit","alert_sourcetype":"unit:alert"}'::jsonb,true) RETURNING id`).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM security_sources WHERE id=$1`, sourceID) })
	connectionChange, err := d.GetFindingDefense(ctx, findingID)
	if err != nil || connectionChange.Scenario == nil || connectionChange.Scenario.State != "current" {
		t.Fatalf("Splunk configuration must not stale finding-only scenario: %+v %v", connectionChange, err)
	}
	if unchanged, err := d.SaveDefenseScenario(ctx, findingID, updatedInput, draft); err != nil || unchanged.Scenario.ID != regenerated.Scenario.ID {
		t.Fatalf("Splunk edit changed scenario cache: %+v %v", unchanged, err)
	}
}

func TestDefenseScenarioInputIgnoresSplunkConfiguration(t *testing.T) {
	d, findingID := purpleDB(t)
	ctx := t.Context()
	before, err := d.GetDefenseScenarioInput(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	var sourceID int64
	err = d.QueryRowContext(ctx, `INSERT INTO security_sources(name,config,enabled)
		VALUES('scenario-multi-stream','{"streams":[{"index":"artex_lab","sourcetype":"lab:audit","kind":"audit"},{"index":"ag_juice_shop","sourcetype":"juice:alert","kind":"alert"}]}'::jsonb,true)
		RETURNING id`).Scan(&sourceID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM security_sources WHERE id=$1`, sourceID) })
	input, err := d.GetDefenseScenarioInput(ctx, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if input.SourceConfigFingerprint != before.SourceConfigFingerprint {
		t.Fatalf("source creation changed finding-only scenario input: before=%s after=%s", before.SourceConfigFingerprint, input.SourceConfigFingerprint)
	}
	if _, err := d.ExecContext(ctx, `UPDATE security_sources SET config=jsonb_set(config,'{streams,1,index}','"ag_juice_shop_changed"'::jsonb) WHERE id=$1`, sourceID); err != nil {
		t.Fatal(err)
	}
	changed, err := d.GetDefenseScenarioInput(ctx, findingID)
	if err != nil || changed.SourceConfigFingerprint != input.SourceConfigFingerprint {
		t.Fatalf("stream edit changed finding-only scenario input: %+v %v", changed, err)
	}
}
