package securitysource

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/investigation"
)

func TestMultiIndexInvestigationAndClosedLoopStayWithinConfiguredPairs(t *testing.T) {
	c := Config{
		BaseURL: "https://splunk.example.test:8089", CorrelationField: "artex_verification_id", ActionField: "action",
		Streams: []LogStream{
			{Index: "ag_juice_shop", Sourcetype: "juice:audit", Kind: "audit"},
			{Index: "ag_juice_shop", Sourcetype: "juice:alert", Kind: "alert"},
			{Index: "ag_vuln_bank", Sourcetype: "bank:audit", Kind: "audit"},
			{Index: "ag_vuln_bank", Sourcetype: "bank:alert", Kind: "alert"},
		},
	}
	scope := historicalScope()
	search, err := BuildInvestigationSearch(c, scope, investigation.DefaultMapping(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []string{
		`(index="ag_juice_shop" sourcetype="juice:audit")`,
		`(index="ag_juice_shop" sourcetype="juice:alert")`,
		`(index="ag_vuln_bank" sourcetype="bank:audit")`,
		`(index="ag_vuln_bank" sourcetype="bank:alert")`,
	} {
		if !strings.Contains(search, pair) {
			t.Errorf("configured source pair missing: %s", pair)
		}
	}
	if strings.Contains(search, "index=*") || strings.Contains(search, `index="ag_juice_shop" (sourcetype="bank:audit"`) {
		t.Fatal("multi-index search broadened its source scope")
	}

	q := sourceQuery()
	baseline, candidate := shadowRules()
	closedLoop, err := BuildClosedLoopRuleSearch(c, q, shadowScope(q), investigation.DefaultMapping(), baseline, candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []string{`(index="ag_juice_shop" sourcetype="juice:audit")`, `(index="ag_vuln_bank" sourcetype="bank:audit")`} {
		if !strings.Contains(closedLoop, pair) {
			t.Errorf("audit source pair missing from closed loop: %s", pair)
		}
	}
	if strings.Contains(closedLoop, "juice:alert") || strings.Contains(closedLoop, "bank:alert") {
		t.Fatal("closed loop included alert events as audit denominator")
	}
}
