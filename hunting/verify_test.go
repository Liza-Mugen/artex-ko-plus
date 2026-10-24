package hunting

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

func TestVerifyRejectsMissingRequiredFieldsEvenWithObservedClaim(t *testing.T) {
	req, design := testRequest(), testDesign()
	design.Stages[0].RequiredFields = append(design.Stages[0].RequiredFields, "process.Image")
	result, err := Verify(req, design, testInvestigation(req))
	if err != nil || result.Stages[0].Status != "insufficient_data" || len(result.Stages[0].MissingFields) != 1 || result.Stages[0].MissingFields[0] != "process.Image" || result.ImpactConfirmed {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestVerifyPartialInvestigationDoesNotBecomeComplete(t *testing.T) {
	req, design := testRequest(), testDesign()
	in := testInvestigation(req)
	in.Status = "insufficient_data"
	out, err := Verify(req, design, in)
	if err != nil || out.Stages[0].Status != "evidence_observed" || out.Status != "insufficient_data" || out.ImpactConfirmed {
		t.Fatalf("partial investigation was upgraded: %+v %v", out, err)
	}
}

func TestVerifyRejectsUncollectedOutOfScopeAndContradictoryRefs(t *testing.T) {
	for _, kind := range []string{"invented_ref", "wrong_source_kind", "wrong_target", "outside_time", "widened_scope", "wrong_mapping", "conflicting_ref", "unknown_stage", "wrong_stage_selector", "missing_raw"} {
		t.Run(kind, func(t *testing.T) {
			req, design := testRequest(), testDesign()
			in := testInvestigation(req)
			switch kind {
			case "invented_ref":
				in.Observations[0].EvidenceRefs = []string{"invented"}
			case "wrong_source_kind":
				in.Collections[0].SourceKind = "file"
			case "wrong_target":
				in.Collections[0].Events[0].Target = "outside.example"
			case "outside_time":
				in.Collections[0].Events[0].Timestamp = req.Scope.End
			case "widened_scope":
				in.Collections[0].Scope.Start = req.Scope.Start.Add(-time.Hour)
			case "wrong_mapping":
				in.Collections[0].Mapping.Target = "other_host"
			case "unknown_stage":
				in.Observations[0].StageID = "not-in-design"
			case "wrong_stage_selector":
				in.Collections[0].Events[0].EventKind = "host"
			case "missing_raw":
				in.Collections[0].Events[0].Raw = ""
			case "conflicting_ref":
				other := in.Collections[0]
				other.Events = append([]investigation.Event{}, other.Events...)
				other.Events[0].Raw = `{"target":"lab.example","path":"/other.php"}`
				in.Collections = append(in.Collections, other)
			}
			out, err := Verify(req, design, in)
			if err != nil || out.Stages[0].Status != "insufficient_data" || out.ImpactConfirmed {
				t.Fatalf("%+v %v", out, err)
			}
		})
	}
}

func TestVerifyKnownVerificationIsNotExternalIntrusionEvidence(t *testing.T) {
	req := testRequest()
	in := testInvestigation(req)
	in.Collections[0].Events[0].KnownARTEX = true
	out, err := Verify(req, testDesign(), in)
	if err != nil || out.Stages[0].Status != "insufficient_data" || len(out.Stages[0].EvidenceRefs) != 0 || len(out.Stages[0].KnownVerificationRefs) != 1 {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestVerifyInferredRequiresNormalAlternativeAndNeverConfirmsImpact(t *testing.T) {
	req := testRequest()
	in := testInvestigation(req)
	in.Observations[0].Kind = "inferred"
	out, err := Verify(req, testDesign(), in)
	if err != nil || out.Stages[0].Status != "insufficient_data" || out.Stages[0].RejectedObservations != 1 {
		t.Fatalf("%+v %v", out, err)
	}
	in.Observations[0].Alternatives = []string{"정상 페이지 접근"}
	out, err = Verify(req, testDesign(), in)
	if err != nil || out.Stages[0].Status != "inferred" || out.ImpactConfirmed {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestVerifyAbsenceRequiresWholeScopeAndAvailableFields(t *testing.T) {
	req := testRequest()
	in := testInvestigation(req)
	in.Observations = nil
	in.Collections[0].Events[0].Path = "/help.html"
	out, err := Verify(req, testDesign(), in)
	if err != nil || out.Stages[0].Status != "not_observed" {
		t.Fatalf("%+v %v", out, err)
	}
	in.ScopeCoverageConfirmed = false
	out, err = Verify(req, testDesign(), in)
	if err != nil || out.Stages[0].Status != "insufficient_data" {
		t.Fatalf("filtered search yielded absence: %+v %v", out, err)
	}
	in.ScopeCoverageConfirmed = true
	in.Collections[0].Scope.Start = req.Scope.Start.Add(time.Second)
	out, err = Verify(req, testDesign(), in)
	if err != nil || out.Stages[0].Status != "insufficient_data" {
		t.Fatalf("narrowed search yielded absence: %+v %v", out, err)
	}
	in.Collections[0].Scope = req.Scope
	in.Collections[0].Events = nil
	out, err = Verify(req, testDesign(), in)
	if err != nil || out.Stages[0].Status != "insufficient_data" {
		t.Fatalf("zero logs yielded a clean result: %+v %v", out, err)
	}
}

func TestVerifyRawNestedFieldsAndSplunkFallbackUseLiteralKeyPrecedence(t *testing.T) {
	for _, test := range []struct{ name, raw, status string }{
		{"nested", `{"process":{"Image":"php"}}`, "evidence_observed"},
		{"literal", `{"process.Image":"php"}`, "evidence_observed"},
		{"literal_null", `{"process.Image":null,"process":{"Image":"php"}}`, "insufficient_data"},
		{"ambiguous_array", `{"process.Image":["php","other"]}`, "insufficient_data"},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, design := testRequest(), testDesign()
			design.Stages[0].RequiredFields = append(design.Stages[0].RequiredFields, "process.Image")
			in := testInvestigation(req)
			wrapper, _ := json.Marshal(map[string]any{"_raw": test.raw})
			in.Collections[0].Events[0].Raw = string(wrapper)
			out, err := Verify(req, design, in)
			if err != nil || out.Stages[0].Status != test.status {
				t.Fatalf("%+v %v", out, err)
			}
		})
	}
}

func TestVerifyDuplicateObservationsAndPartialStagesDoNotInventCompletion(t *testing.T) {
	req, design := testRequest(), testDesign()
	in := testInvestigation(req)
	in.Observations = append(in.Observations, in.Observations[0])
	next := design.Stages[0]
	next.ID, next.DependsOn, next.RequiredFields = "stage-2", []string{"stage-1"}, []string{"process.Image"}
	design.Stages = append(design.Stages, next)
	out, err := Verify(req, design, in)
	if err != nil || out.Status != "insufficient_data" || out.Stages[0].Status != "evidence_observed" || out.Stages[1].Status != "insufficient_data" || len(out.Stages[0].EvidenceRefs) != 1 || out.Stages[0].RejectedObservations != 0 {
		t.Fatalf("%+v %v", out, err)
	}
}
