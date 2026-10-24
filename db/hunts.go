package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrHuntNotFound = errors.New("자율 헌팅을 찾을 수 없습니다")
var ErrHuntActive = errors.New("다른 자율 헌팅이 진행 중입니다")
var ErrHuntInactive = errors.New("자율 헌팅이 종료되었습니다")

// Hunt is independent of findings, defense scenarios and historical cases.
// Request is an immutable authorization contract; terminal records are sealed.
type Hunt struct {
	ID        int64           `json:"id,string"`
	Status    string          `json:"status"`
	Request   json.RawMessage `json:"request"`
	Events    []HuntEvent     `json:"events"`
	Result    json.RawMessage `json:"result"`
	Error     string          `json:"error"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}
type HuntEvent struct {
	Sequence  int             `json:"sequence"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt time.Time       `json:"created_at"`
}
type HuntSummary struct {
	ID        int64     `json:"id,string"`
	Status    string    `json:"status"`
	Term      string    `json:"term"`
	Error     string    `json:"error"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const huntCols = `id,status,request,events,result,error,created_at,updated_at`

func scanHunt(row interface{ Scan(...any) error }) (*Hunt, error) {
	h := &Hunt{}
	var events []byte
	err := row.Scan(&h.ID, &h.Status, &h.Request, &events, &h.Result, &h.Error, &h.CreatedAt, &h.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrHuntNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(events, &h.Events); err != nil {
		return nil, err
	}
	return h, nil
}
func (d *DB) GetHunt(ctx context.Context, id int64) (*Hunt, error) {
	return scanHunt(d.QueryRowContext(ctx, `SELECT `+huntCols+` FROM defensive_hunts WHERE id=$1`, id))
}
func (d *DB) ListHunts(ctx context.Context) ([]HuntSummary, error) {
	rows, err := d.QueryContext(ctx, `SELECT id,status,request->>'term',error,created_at,updated_at FROM defensive_hunts ORDER BY id DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HuntSummary{}
	for rows.Next() {
		var h HuntSummary
		if err = rows.Scan(&h.ID, &h.Status, &h.Term, &h.Error, &h.CreatedAt, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Advisory transaction lock plus a unique partial index also protects admission
// across processes. Repeated clicks with the same immutable request are free.
func (d *DB) CreateHunt(ctx context.Context, request json.RawMessage) (*Hunt, bool, error) {
	request, err := investigationRunObject(request, 64<<10)
	if err != nil {
		return nil, false, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7337741042)`); err != nil {
		return nil, false, err
	}
	active, err := scanHunt(tx.QueryRowContext(ctx, `SELECT `+huntCols+` FROM defensive_hunts WHERE status IN ('queued','running')`))
	if err == nil {
		var same bool
		if err = tx.QueryRowContext(ctx, `SELECT request=$2::jsonb FROM defensive_hunts WHERE id=$1`, active.ID, request).Scan(&same); err != nil {
			return nil, false, err
		}
		if !same {
			return nil, false, ErrHuntActive
		}
		return active, false, tx.Commit()
	}
	if !errors.Is(err, ErrHuntNotFound) {
		return nil, false, err
	}
	h, err := scanHunt(tx.QueryRowContext(ctx, `INSERT INTO defensive_hunts(request) VALUES($1) RETURNING `+huntCols, request))
	if err != nil {
		return nil, false, err
	}
	return h, true, tx.Commit()
}
func (d *DB) StartHunt(ctx context.Context, id int64) (bool, error) {
	r, err := d.ExecContext(ctx, `UPDATE defensive_hunts SET status='running',updated_at=clock_timestamp() WHERE id=$1 AND status='queued'`, id)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (d *DB) AppendHuntEvent(ctx context.Context, id int64, kind string, payload json.RawMessage) error {
	if len(kind) < 1 || len(kind) > 80 {
		return ErrDefenseInvalid
	}
	payload, err := investigationRunObject(payload, 12<<20)
	if err != nil {
		return err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	var count, size int
	err = tx.QueryRowContext(ctx, `SELECT status,jsonb_array_length(events),octet_length(events::text) FROM defensive_hunts WHERE id=$1 FOR UPDATE`, id).Scan(&status, &count, &size)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrHuntNotFound
	}
	if err != nil {
		return err
	}
	if status != "running" {
		return ErrHuntInactive
	}
	if count >= 256 || size+len(payload) > 20<<20 {
		return fmt.Errorf("%w: 헌팅 근거 저장 한도", ErrDefenseInvalid)
	}
	e := HuntEvent{Sequence: count + 1, Kind: kind, Payload: payload, CreatedAt: time.Now().UTC()}
	raw, _ := json.Marshal([]HuntEvent{e})
	_, err = tx.ExecContext(ctx, `UPDATE defensive_hunts SET events=events||$2::jsonb,updated_at=clock_timestamp() WHERE id=$1`, id, raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (d *DB) FinishHunt(ctx context.Context, id int64, status string, result json.RawMessage, message string) (bool, error) {
	switch status {
	case "completed", "insufficient_data", "budget_exhausted", "cancelled", "interrupted", "model_error", "research_failed", "failed":
	default:
		return false, ErrDefenseInvalid
	}
	result, err := investigationRunObject(result, 20<<20)
	if err != nil {
		return false, err
	}
	if len(message) > 8000 {
		message = message[:8000]
	}
	r, err := d.ExecContext(ctx, `UPDATE defensive_hunts SET status=$2,result=$3,error=$4,updated_at=clock_timestamp() WHERE id=$1 AND status IN ('queued','running')`, id, status, result, message)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (d *DB) CancelHunt(ctx context.Context, id int64) (*Hunt, error) {
	_, err := d.ExecContext(ctx, `UPDATE defensive_hunts SET status='cancelled',error='사용자가 헌팅을 중단했습니다',updated_at=clock_timestamp() WHERE id=$1 AND status IN ('queued','running')`, id)
	if err != nil {
		return nil, err
	}
	return d.GetHunt(ctx, id)
}
func (d *DB) RecoverHunts(ctx context.Context) (int64, error) {
	r, err := d.ExecContext(ctx, `UPDATE defensive_hunts SET status='interrupted',error='서비스 재시작으로 중단되었습니다. 보존된 근거를 검토한 뒤 새로 실행하세요',updated_at=clock_timestamp() WHERE status IN ('queued','running')`)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
