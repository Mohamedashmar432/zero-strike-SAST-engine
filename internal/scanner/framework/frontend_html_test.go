package framework

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

)

func TestRawHTMLBindingCheckRegistered(t *testing.T) {
	found := false
	for _, c := range checks {
		if c.ruleID == "ZS-CFG-020" {
			found = true
		}
	}
	if !found {
		t.Fatal("ZS-CFG-020 must be in the checks list or it never runs")
	}
}

func TestRawHTMLBindingCheck(t *testing.T) {
	path := fixtureRoot + "/frontend/vuln_bypass.component.html"
	vuln := detectRawHTMLBinding(path, readFixture(t, "frontend/vuln_bypass.component.html"))
	if len(vuln) != 1 || vuln[0].RuleID != "ZS-CFG-020" {
		t.Fatalf("expected 1 ZS-CFG-020 finding, got %+v", vuln)
	}
	if vuln[0].Tier == core.TierHardening || vuln[0].Config.Framework != "angular" {
		t.Errorf("expected a non-hardening angular finding, got tier=%q framework=%q", vuln[0].Tier, vuln[0].Config.Framework)
	}

	cleanPath := fixtureRoot + "/frontend/clean_default.component.html"
	if clean := detectRawHTMLBinding(cleanPath, readFixture(t, "frontend/clean_default.component.html")); len(clean) != 0 {
		t.Errorf("expected no finding without a sanitizer bypass, got %+v", clean)
	}
}
