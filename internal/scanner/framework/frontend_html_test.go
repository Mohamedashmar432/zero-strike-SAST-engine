package framework

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

)

// ZS-CFG-020 is retired for measured precision, see commit 37cf7e3 and the note
// in scanner.go: it must stay out of the checks list so it never runs.
func TestRawHTMLBindingCheckRetiredNotRegistered(t *testing.T) {
	for _, c := range checks {
		if c.ruleID == "ZS-CFG-020" {
			t.Fatal("ZS-CFG-020 is retired and must not be in the checks list")
		}
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
