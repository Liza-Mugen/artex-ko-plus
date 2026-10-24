// Package hunting coordinates a read-only, evidence-linked threat hunt. It is
// independent of finding defense-scenario generation and never executes attacks
// or deploys rules. Runtime and source adapters are supplied by the caller.
package hunting

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

const EngineVersion = "autonomous-hunting-v1"

const (
	MaxStages             = 4
	MaxResearchSources    = 8
	MaxCollections        = 16
	MaxEvidenceEvents     = 8000
	MaxEvidenceBytes      = 32 << 20
	MaxEvents             = 200
	MaxEventBytes         = 20 << 20
	MaxEvidenceEventBytes = 12 << 20
	RunTimeout            = 20 * time.Minute
)

var (
	ErrInvalid   = errors.New("헌팅 입력 또는 근거 형식이 올바르지 않습니다")
	ErrBudget    = errors.New("헌팅 실행 한도를 소진했습니다")
	ErrRunClosed = errors.New("헌팅 실행이 이미 종료되었습니다")
)

type Request struct {
	Term                   string                `json:"term"`
	Scope                  investigation.Scope   `json:"scope"`
	Mapping                investigation.Mapping `json:"mapping"`
	SourceID               int64                 `json:"source_id,string"`
	ExpectedSourceRevision int64                 `json:"expected_source_revision"`
	Sourcetypes            []string              `json:"sourcetypes"`
	ResearchURLs           []string              `json:"research_urls,omitempty"`
}

// SHA256 identifies the exact retained Excerpt bytes, not a signature or proof
// of a publisher's claims. A research adapter must fetch before setting FetchedAt.
type ResearchSource struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Title     string    `json:"title"`
	Excerpt   string    `json:"excerpt"`
	SHA256    string    `json:"sha256"`
	FetchedAt time.Time `json:"fetched_at"`
}

type ResearchClaim struct {
	Text      string   `json:"text"`
	SourceIDs []string `json:"source_ids"`
}

type Research struct {
	Term     string           `json:"term"`
	Summary  string           `json:"summary"`
	CVEs     []string         `json:"cves"`
	Sources  []ResearchSource `json:"sources"`
	Claims   []ResearchClaim  `json:"claims"`
	Warnings []string         `json:"warnings"`
}

// A Stage describes a hypothetical attack and an evidence question. Free-text
// SuccessCriteria and AttackDescription are not executable queries or verdicts.
// RequiredFields contains normalized event field names or exact raw JSON paths.
type Stage struct {
	ID                 string   `json:"id"`
	AttackDescription  string   `json:"attack_description"`
	DetectionQuestion  string   `json:"detection_question"`
	RequiredFields     []string `json:"required_fields"`
	SuccessCriteria    string   `json:"success_criteria"`
	BenignAlternatives []string `json:"benign_alternatives"`
	SourceIDs          []string `json:"source_ids"`
	EventKinds         []string `json:"event_kinds,omitempty"`
	PathContains       []string `json:"path_contains,omitempty"`
	DependsOn          []string `json:"depends_on,omitempty"`
}

type Design struct {
	Title   string  `json:"title"`
	Summary string  `json:"summary"`
	Stages  []Stage `json:"stages"`
}

type Observation struct {
	StageID      string   `json:"stage_id"`
	Kind         string   `json:"kind"` // observed, inferred, insufficient_data
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
	Alternatives []string `json:"alternatives"`
	NextSteps    []string `json:"next_steps"`
}

type Usage struct {
	Rounds        int64 `json:"rounds"`
	ModelCalls    int64 `json:"model_calls"`
	Queries       int64 `json:"queries"`
	RemoteQueries int64 `json:"remote_queries"`
	InputTokens   int64 `json:"input_tokens"`
	OutputTokens  int64 `json:"output_tokens"`
}

type InvestigationResult struct {
	Status       string                     `json:"status"`
	Summary      string                     `json:"summary"`
	Observations []Observation              `json:"observations"`
	Collections  []investigation.Collection `json:"collections"`
	// Only the source adapter can attest that a completed, unfiltered bootstrap
	// search covered the whole requested scope. Missing this flag never permits
	// an absence conclusion from a narrowed follow-up search.
	ScopeCoverageConfirmed bool     `json:"scope_coverage_confirmed"`
	Usage                  Usage    `json:"usage"`
	Gaps                   []string `json:"gaps"`
	NextSteps              []string `json:"next_steps"`
}

type StageAssessment struct {
	StageID               string   `json:"stage_id"`
	Status                string   `json:"status"` // evidence_observed, inferred, not_observed, insufficient_data
	Summary               string   `json:"summary"`
	EvidenceRefs          []string `json:"evidence_refs"`
	KnownVerificationRefs []string `json:"known_verification_refs"`
	MissingFields         []string `json:"missing_fields"`
	Reasons               []string `json:"reasons"`
	Alternatives          []string `json:"alternatives"`
	NextSteps             []string `json:"next_steps"`
	RejectedObservations  int      `json:"rejected_observations"`
}

type Verification struct {
	Status          string            `json:"status"`
	Summary         string            `json:"summary"`
	Stages          []StageAssessment `json:"stages"`
	Warnings        []string          `json:"warnings"`
	ImpactConfirmed bool              `json:"impact_confirmed"`
}

type Event struct {
	Sequence int64           `json:"sequence"`
	Stage    string          `json:"stage"`
	Kind     string          `json:"kind"`
	Summary  string          `json:"summary"`
	Detail   string          `json:"detail,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	At       time.Time       `json:"at"`
}

type Result struct {
	EngineVersion string              `json:"engine_version"`
	Status        string              `json:"status"`
	Stage         string              `json:"stage"`
	StartedAt     time.Time           `json:"started_at"`
	FinishedAt    time.Time           `json:"finished_at"`
	Research      Research            `json:"research"`
	Design        Design              `json:"design"`
	Investigation InvestigationResult `json:"investigation"`
	Verification  Verification        `json:"verification"`
	Events        []Event             `json:"events"`
	Error         string              `json:"error,omitempty"`
}

// Investigate must perform source authorization/revision checks at every remote
// request. emit returns an error when persistence/cancellation/budgets stop work;
// adapters must propagate it. Only read-only runtime tools belong in this hook.
type Dependencies struct {
	Research    func(context.Context, Request) (Research, error)
	Design      func(context.Context, Request, Research) (Design, error)
	Investigate func(context.Context, Request, Design, func(Event) error) (InvestigationResult, error)
	Emit        func(Event) error
}
