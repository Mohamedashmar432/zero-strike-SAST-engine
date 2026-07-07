package rules_test

import (
	"strings"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/rules"
)

func validRule() *rules.Rule {
	return &rules.Rule{
		ID:         "ZS-TEST-001",
		Severity:   core.SeverityHigh,
		Confidence: core.ConfidenceHigh,
		Lifecycle:  "released",
		Match: rules.MatchPattern{
			Kind:   string(ir.NodeKindCall),
			Callee: "eval",
		},
	}
}

func TestValidator_ValidRule(t *testing.T) {
	errs := rules.NewValidator().Validate(validRule())
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid rule, got: %v", errs)
	}
}

func TestValidator_MissingKind(t *testing.T) {
	r := validRule()
	r.Match.Kind = ""
	assertError(t, r, "match.kind")
}

func TestValidator_UnknownKind(t *testing.T) {
	r := validRule()
	r.Match.Kind = "foobar"
	assertError(t, r, "match.kind")
}

func TestValidator_CallWithoutCallee(t *testing.T) {
	r := validRule()
	r.Match.Kind = string(ir.NodeKindCall)
	r.Match.Callee = ""
	assertError(t, r, "match.callee")
}

func TestValidator_InvalidSeverity(t *testing.T) {
	r := validRule()
	r.Severity = "extreme"
	assertError(t, r, "severity")
}

func TestValidator_InvalidConfidence(t *testing.T) {
	r := validRule()
	r.Confidence = "very_high"
	assertError(t, r, "confidence")
}

func assertError(t *testing.T, r *rules.Rule, field string) {
	t.Helper()
	errs := rules.NewValidator().Validate(r)
	if len(errs) == 0 {
		t.Fatalf("expected validation error containing %q, got none", field)
	}
	for _, e := range errs {
		if strings.Contains(e, field) {
			return
		}
	}
	t.Errorf("expected error containing %q, got: %v", field, errs)
}
