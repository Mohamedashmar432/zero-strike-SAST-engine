package rules

import (
	"fmt"

	"github.com/zerostrike/scanner/internal/ir"
)

var validNodeKinds = map[string]bool{
	string(ir.NodeKindModule):     true,
	string(ir.NodeKindFunction):   true,
	string(ir.NodeKindClass):      true,
	string(ir.NodeKindCall):       true,
	string(ir.NodeKindAssignment): true,
	string(ir.NodeKindImport):     true,
	string(ir.NodeKindLiteral):    true,
	string(ir.NodeKindIdentifier): true,
	string(ir.NodeKindBlock):      true,
	string(ir.NodeKindReturn):     true,
	string(ir.NodeKindIf):         true,
	string(ir.NodeKindFor):        true,
	string(ir.NodeKindWhile):      true,
	string(ir.NodeKindTry):        true,
	string(ir.NodeKindAttribute):  true,
	string(ir.NodeKindBinaryOp):   true,
	string(ir.NodeKindAssert):     true,
}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

var validConfidences = map[string]bool{
	"high": true, "medium": true, "low": true,
}

var validLifecycles = map[string]bool{
	"draft": true, "validated": true, "released": true, "retired": true,
}

type defaultValidator struct{}

// NewValidator returns a Validator that rejects unindexable and malformed rules.
func NewValidator() Validator { return &defaultValidator{} }

// Validate returns a list of field-level error messages for any malformed rule.
// An empty slice means the rule is valid.
func (v *defaultValidator) Validate(rule *Rule) []string {
	var errs []string
	switch {
	case rule.Match.Kind == "":
		errs = append(errs, "match.kind: required")
	case !validNodeKinds[rule.Match.Kind]:
		errs = append(errs, fmt.Sprintf("match.kind: unknown value %q", rule.Match.Kind))
	case rule.Match.Kind == string(ir.NodeKindCall) && rule.Match.Callee == "":
		errs = append(errs, "match.callee: required for kind=call")
	}
	if !validSeverities[string(rule.Severity)] {
		errs = append(errs, fmt.Sprintf("severity: invalid value %q", rule.Severity))
	}
	if !validConfidences[string(rule.Confidence)] {
		errs = append(errs, fmt.Sprintf("confidence: invalid value %q", rule.Confidence))
	}
	if !validLifecycles[rule.Lifecycle] {
		errs = append(errs, fmt.Sprintf("lifecycle: invalid value %q", rule.Lifecycle))
	}
	return errs
}
