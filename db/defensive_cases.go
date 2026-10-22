package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

var ErrDefensiveCaseNotFound = errors.New("방어 조사 사건을 찾을 수 없습니다")
var ErrDefensiveCaseActive = errors.New("진행 중인 AI 조사를 중지한 뒤 사건을 삭제해 주세요")

// A case owns its evidence. A finding is an optional immutable context snapshot,
// never a prerequisite and never synthesized as a side effect of log analysis.
type DefensiveCase struct {
	ID                int64                         `json:"id,string"`
	FindingID         int64                         `json:"finding_id,string,omitempty"`
	Title             string                        `json:"title"`
	Question          string                        `json:"question"`
	SourceKind        string                        `json:"source_kind"`
	SourceID          int64                         `json:"source_id,string"`
	SourceRevision    int64                         `json:"source_revision"`
	SourceSnapshot    json.RawMessage               `json:"source_snapshot"`
	Scope             investigation.Scope           `json:"scope"`
	Mapping           investigation.Mapping         `json:"mapping"`
	Plan              investigation.Plan            `json:"plan"`
	FindingSnapshot   *investigation.FindingContext `json:"finding_snapshot,omitempty"`
	Collection        investigation.Collection      `json:"collection"`
	Analysis          investigation.Analysis        `json:"analysis"`
	EvidenceVersion   int64                         `json:"evidence_version,omitempty"`
	SourceFingerprint string                        `json:"source_fingerprint,omitempty"`
	CreatedAt         time.Time                     `json:"created_at"`
	State             string                        `json:"state"`
}

type DefensiveCaseSummary struct {
	ID              int64               `json:"id,string"`
	FindingID       int64               `json:"finding_id,string,omitempty"`
	Title           string              `json:"title"`
	Question        string              `json:"question"`
	SourceKind      string              `json:"source_kind"`
	Scope           investigation.Scope `json:"scope"`
	Summary         string              `json:"summary"`
	ObservedCount   int                 `json:"observed_count"`
	KnownARTEXCount int                 `json:"known_artex_count"`
	Complete        bool                `json:"complete"`
	CreatedAt       time.Time           `json:"created_at"`
}

type DefensiveCaseOverview struct {
	Cases            []DefensiveCaseSummary `json:"cases"`
	Total            int64                  `json:"total"`
	HistoryTruncated bool                   `json:"history_truncated"`
}

func (d *DB) SaveDefensiveCase(ctx context.Context, in DefensiveCase) (*DefensiveCase, error) {
	var err error
	if in.Title, err = defenseText(in.Title, "사건 제목", 1, 200); err != nil {
		return nil, err
	}
	if in.Question, err = defenseText(in.Question, "조사 질문", 0, 4000); err != nil {
		return nil, err
	}
	if in.SourceKind != "file" && in.SourceKind != "splunk" {
		return nil, ErrDefenseInvalid
	}
	if err = investigation.ValidateScope(in.Scope, time.Now()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDefenseInvalid, err)
	}
	if err = investigation.ValidateMapping(in.Mapping); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDefenseInvalid, err)
	}
	if in.Collection.Scope != in.Scope || in.Collection.Mapping != in.Mapping || in.Collection.SourceKind != in.SourceKind {
		return nil, ErrDefenseInvalid
	}
	if len(in.Collection.Events) > investigation.MaxEvents {
		return nil, ErrDefenseInvalid
	}
	in.SourceSnapshot, err = investigationRunObject(in.SourceSnapshot, 64<<10)
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	in.ID = 0
	in.CreatedAt = time.Time{}
	in.State = "current"
	in.Plan = investigation.BuildDefensivePlan()
	in.FindingSnapshot = nil
	if in.FindingID > 0 {
		if err = LockFindingEvidenceTx(tx, in.FindingID, nil); err != nil {
			return nil, err
		}
		current, e := investigationContextTx(ctx, tx, in.FindingID)
		if e != nil {
			return nil, e
		}
		if current.EvidenceVersion != in.EvidenceVersion || current.SourceFingerprint != in.SourceFingerprint {
			return nil, ErrDefenseConflict
		}
		snapshot := current.Context
		in.FindingSnapshot = &snapshot
		in.Plan = current.Plan
	} else if in.FindingID < 0 || in.EvidenceVersion != 0 || in.SourceFingerprint != "" {
		return nil, ErrDefenseInvalid
	}
	if in.SourceKind == "splunk" {
		var revision int64
		var enabled bool
		if err = tx.QueryRowContext(ctx, `SELECT revision,enabled FROM security_sources WHERE id=$1 FOR SHARE`, in.SourceID).Scan(&revision, &enabled); errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSecuritySourceNotFound
		} else if err != nil {
			return nil, err
		}
		if !enabled || revision != in.SourceRevision {
			return nil, ErrDefenseConflict
		}
	} else if in.SourceID != 0 || in.SourceRevision != 0 {
		return nil, ErrDefenseInvalid
	}
	in.Analysis = investigation.Analyze(in.Plan, in.Scope, in.Collection)
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	if len(raw) > 32<<20 {
		return nil, fmt.Errorf("%w: 사건 기록이 너무 큽니다", ErrDefenseInvalid)
	}
	var finding any
	if in.FindingID > 0 {
		finding = in.FindingID
	}
	if err = tx.QueryRowContext(ctx, `INSERT INTO defensive_cases(finding_id,payload) VALUES($1,$2) RETURNING id,created_at`, finding, raw).Scan(&in.ID, &in.CreatedAt); err != nil {
		return nil, err
	}
	return &in, tx.Commit()
}

func (d *DB) GetDefensiveCase(ctx context.Context, id int64) (*DefensiveCase, error) {
	var raw []byte
	var created time.Time
	err := d.QueryRowContext(ctx, `SELECT payload,created_at FROM defensive_cases WHERE id=$1`, id).Scan(&raw, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDefensiveCaseNotFound
	}
	if err != nil {
		return nil, err
	}
	out := &DefensiveCase{}
	if err = json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	out.ID = id
	out.CreatedAt = created
	return out, nil
}

// DeleteDefensiveCase removes the case and its owned AI runs. Locking the case
// serializes deletion with CreateDefensiveCaseRun, and active runs must first be
// cancelled so their worker cannot write into a deleted record.
func (d *DB) DeleteDefensiveCase(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrDefenseInvalid
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked int64
	if err = tx.QueryRowContext(ctx, `SELECT id FROM defensive_cases WHERE id=$1 FOR UPDATE`, id).Scan(&locked); errors.Is(err, sql.ErrNoRows) {
		return ErrDefensiveCaseNotFound
	} else if err != nil {
		return err
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM defensive_case_runs WHERE case_id=$1 AND status IN ('queued','running'))`, id).Scan(&active); err != nil {
		return err
	}
	if active {
		return ErrDefensiveCaseActive
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM defensive_cases WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) ListDefensiveCases(ctx context.Context) (*DefensiveCaseOverview, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := &DefensiveCaseOverview{Cases: []DefensiveCaseSummary{}}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM defensive_cases`).Scan(&out.Total); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,COALESCE(finding_id,0),payload->>'title',payload->>'question',payload->>'source_kind',payload->'scope',payload#>>'{analysis,summary}',(payload#>>'{analysis,observed_count}')::int,(payload#>>'{analysis,known_artex_count}')::int,(payload#>>'{collection,complete}')::boolean,created_at FROM defensive_cases ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var item DefensiveCaseSummary
		var scope []byte
		if err = rows.Scan(&item.ID, &item.FindingID, &item.Title, &item.Question, &item.SourceKind, &scope, &item.Summary, &item.ObservedCount, &item.KnownARTEXCount, &item.Complete, &item.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		if err = json.Unmarshal(scope, &item.Scope); err != nil {
			rows.Close()
			return nil, err
		}
		out.Cases = append(out.Cases, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out.HistoryTruncated = out.Total > int64(len(out.Cases))
	return out, tx.Commit()
}

// Registered verification traffic across all findings is distinguished from
// historical events. Matching a marker still requires its actual run window.
func (d *DB) KnownDefensiveVerifications(ctx context.Context, scope investigation.Scope) ([]InvestigationVerification, error) {
	rows, err := d.QueryContext(ctx, `SELECT e.correlation_id::text,`+executionRetestSQL+` FROM finding_defense_executions e LEFT JOIN finding_retests r ON r.id=e.retest_id AND r.finding_id=e.finding_id WHERE COALESCE((`+executionRetestSQL+`->>'started_at')::timestamptz,'infinity'::timestamptz)<=$2 AND COALESCE((`+executionRetestSQL+`->>'finished_at')::timestamptz,'-infinity'::timestamptz)>=$1 ORDER BY e.id`, scope.Start.Add(-time.Minute), scope.End.Add(30*time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InvestigationVerification{}
	for rows.Next() {
		var item InvestigationVerification
		var raw []byte
		if err = rows.Scan(&item.ID, &raw); err != nil {
			return nil, err
		}
		var retest FindingRetest
		if err = json.Unmarshal(raw, &retest); err != nil {
			return nil, err
		}
		if retest.StartedAt == nil || retest.FinishedAt == nil {
			continue
		}
		item.Start = retest.StartedAt.Add(-30 * time.Second)
		item.End = retest.FinishedAt.Add(time.Minute)
		out = append(out, item)
	}
	return out, rows.Err()
}
