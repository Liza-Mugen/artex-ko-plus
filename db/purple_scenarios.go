package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

// Keep the historical source_config_fingerprint column as a generation
// contract version. Scenario drafts now depend on the finding alone, so a
// Splunk connection edit must not invalidate or populate them.
var defenseScenarioContractFingerprint = func() string {
	h := sha256.Sum256([]byte("finding-only-defense-scenario-v2"))
	return hex.EncodeToString(h[:])
}()

// DefenseScenario is a draft to guide an operator. Presence and rule results
// are never inferred from a configured Splunk connection or an AI response.
type DefenseScenario struct {
	ID                int64                  `json:"id,string"`
	State             string                 `json:"state"`
	EvidenceVersion   int64                  `json:"evidence_version"`
	SourceFingerprint string                 `json:"source_fingerprint"`
	CreatedAt         time.Time              `json:"created_at"`
	Title             string                 `json:"title"`
	AttackSteps       []DefenseAttackStep    `json:"attack_steps"`
	Stages            []DefenseScenarioStage `json:"stages"`
}

type DefenseAttackStep struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Basis       string `json:"basis"`
	Evidence    string `json:"evidence"`
}

type DefenseEquipment struct {
	Kind     string `json:"kind"`
	Presence string `json:"presence"`
	Basis    string `json:"basis"`
}

type DefenseSplunkSource struct {
	ID              int64                 `json:"id,string"`
	Name            string                `json:"name"`
	Index           string                `json:"index"`
	AuditSourcetype string                `json:"audit_sourcetype"`
	AlertSourcetype string                `json:"alert_sourcetype"`
	Streams         []DefenseSplunkStream `json:"streams,omitempty"`
	Status          string                `json:"status"`
	Revision        int64                 `json:"-"`
}

type DefenseSplunkStream struct {
	Index      string `json:"index"`
	Sourcetype string `json:"sourcetype"`
	Kind       string `json:"kind"`
	Label      string `json:"label,omitempty"`
	Asset      string `json:"asset,omitempty"`
}

type DefenseRuleDraft struct {
	Format    string `json:"format"`
	Query     string `json:"query"`
	Rationale string `json:"rationale"`
}

type DefenseScenarioStage struct {
	ID              string                `json:"id"`
	AttackStepID    string                `json:"attack_step_id"`
	Title           string                `json:"title"`
	Equipment       []DefenseEquipment    `json:"equipment"`
	LogSources      []string              `json:"log_sources"`
	RequiredFields  []string              `json:"required_fields"`
	SplunkSources   []DefenseSplunkSource `json:"splunk_sources,omitempty"`
	RuleDraft       DefenseRuleDraft      `json:"rule_draft"`
	BenignBaseline  string                `json:"benign_baseline"`
	SuccessCriteria string                `json:"success_criteria"`
	Limitations     []string              `json:"limitations"`
}

type DefenseScenarioInput struct {
	Finding                 investigation.FindingContext
	TaskID                  int64
	EvidenceVersion         int64
	SourceFingerprint       string
	SourceConfigFingerprint string
}

func defenseScenarioInputTx(ctx context.Context, tx *sql.Tx, findingID int64) (*DefenseScenarioInput, error) {
	in := &DefenseScenarioInput{SourceConfigFingerprint: defenseScenarioContractFingerprint}
	var source []byte
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(f.task_id,0),f.evidence_version,`+investigationFingerprintSQL+`,`+investigationContextSQL+` FROM findings f WHERE f.id=$1`, findingID).
		Scan(&in.TaskID, &in.EvidenceVersion, &in.SourceFingerprint, &source)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrFindingNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(source, &in.Finding); err != nil {
		return nil, err
	}
	return in, nil
}

func (d *DB) GetDefenseScenarioInput(ctx context.Context, findingID int64) (*DefenseScenarioInput, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	in, err := defenseScenarioInputTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	return in, tx.Commit()
}

func defenseScenarioTx(ctx context.Context, tx *sql.Tx, findingID int64) (*DefenseScenario, error) {
	in, err := defenseScenarioInputTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	var id, version int64
	var fingerprint, configFingerprint string
	var raw []byte
	var created time.Time
	err = tx.QueryRowContext(ctx, `SELECT id,evidence_version,source_fingerprint,source_config_fingerprint,payload,created_at
		FROM finding_defense_scenarios WHERE finding_id=$1`, findingID).
		Scan(&id, &version, &fingerprint, &configFingerprint, &raw, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &DefenseScenario{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	// Old saved drafts can contain the former unfiltered connection list.
	// Keep the stored payload for history, but never return those candidates.
	for i := range out.Stages {
		out.Stages[i].SplunkSources = nil
	}
	out.ID, out.EvidenceVersion, out.SourceFingerprint, out.CreatedAt = id, version, fingerprint, created
	out.State = "stale"
	if version == in.EvidenceVersion && fingerprint == in.SourceFingerprint && configFingerprint == in.SourceConfigFingerprint {
		out.State = "current"
	}
	return out, nil
}

// SaveDefenseScenario checks the same finding and generation contract used to
// pay for generation. Concurrent evidence edits cannot make a new draft look
// current. A matching draft is reused without changing its ID or timestamp.
func (d *DB) SaveDefenseScenario(ctx context.Context, findingID int64, in *DefenseScenarioInput, scenario DefenseScenario) (*FindingDefense, error) {
	if in == nil || findingID <= 0 || in.SourceFingerprint == "" || in.SourceConfigFingerprint == "" {
		return nil, ErrDefenseInvalid
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := LockFindingEvidenceTx(tx, findingID, nil); err != nil {
		return nil, err
	}
	current, err := defenseScenarioInputTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	if current.EvidenceVersion != in.EvidenceVersion || current.SourceFingerprint != in.SourceFingerprint || current.SourceConfigFingerprint != in.SourceConfigFingerprint {
		return nil, ErrDefenseConflict
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM finding_defense_scenarios WHERE finding_id=$1
		AND evidence_version=$2 AND source_fingerprint=$3 AND source_config_fingerprint=$4)`,
		findingID, in.EvidenceVersion, in.SourceFingerprint, in.SourceConfigFingerprint).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		// Metadata is stored in columns; the JSON body holds only the draft.
		scenario.ID = 0
		scenario.State = ""
		scenario.EvidenceVersion = 0
		scenario.SourceFingerprint = ""
		scenario.CreatedAt = time.Time{}
		for i := range scenario.Stages {
			scenario.Stages[i].SplunkSources = nil
		}
		raw, err := json.Marshal(scenario)
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO finding_defense_scenarios(finding_id,evidence_version,source_fingerprint,source_config_fingerprint,payload)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT(finding_id) DO UPDATE SET
			evidence_version=EXCLUDED.evidence_version,source_fingerprint=EXCLUDED.source_fingerprint,
			source_config_fingerprint=EXCLUDED.source_config_fingerprint,payload=EXCLUDED.payload,created_at=clock_timestamp()`,
			findingID, in.EvidenceVersion, in.SourceFingerprint, in.SourceConfigFingerprint, raw)
		if err != nil {
			return nil, err
		}
	}
	out, err := findingDefenseTx(ctx, tx, findingID)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
