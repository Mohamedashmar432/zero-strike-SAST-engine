package rules_test

import (
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
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

// A single-segment callee_suffix matches the method on ANY receiver, which is
// what stops sink rules being pinned to one hardcoded variable name
// (`cursor.execute` missed `cur.execute` / `conn.execute` / `session.execute`).
// It is only safe on a rule that gates the match with filters: an unbounded
// "eval" suffix rule would fire on any parser.eval() call.
func TestValidator_CalleeSuffixSingleSegmentRequiresFilters(t *testing.T) {
	r := validRule()
	r.Match.Callee = "eval"
	r.Match.CalleeSuffix = true
	r.Match.Filters = nil
	assertError(t, r, "match.callee_suffix")
}

func TestValidator_CalleeSuffixSingleSegmentAllowedWithFilters(t *testing.T) {
	r := validRule()
	r.Match.Callee = "execute"
	r.Match.CalleeSuffix = true
	r.Match.Filters = []rules.Filter{{TaintedArgument: true}}
	if errs := rules.NewValidator().Validate(r); len(errs) != 0 {
		t.Errorf("taint-gated single-segment callee_suffix should validate, got %v", errs)
	}
}

func TestValidator_CalleeSuffixAllowedWithTwoSegments(t *testing.T) {
	r := validRule()
	r.Match.Callee = "Response.Write"
	r.Match.CalleeSuffix = true
	errs := rules.NewValidator().Validate(r)
	if len(errs) != 0 {
		t.Errorf("expected no errors for a 2-segment callee_suffix rule, got: %v", errs)
	}
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
