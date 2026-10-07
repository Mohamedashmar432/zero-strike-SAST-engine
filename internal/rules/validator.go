package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
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
	string(ir.NodeKindDecorator):  true,
	string(ir.NodeKindKeywordArg): true,
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
	case rule.Match.Kind == string(ir.NodeKindCall) && rule.Match.Callee == "" && len(rule.Match.Filters) == 0:
		// A call rule with no callee AND no filters would match every call
		// node in every file — the footgun this guard exists to prevent. A
		// filter-constrained call rule (e.g. kwarg_name_matches "^on[a-z]+$"
		// for inline HTML event handlers, which must be tag-agnostic) is
		// legitimately callee-less and allowed.
		errs = append(errs, "match.callee: required for kind=call unless filters constrain the match")
	}
	// An unrecognised node kind in argument_kind_not_at would make the filter
	// silently match nothing, which is the failure mode this whole change set
	// exists to remove. Reject it at load time instead.
	for i, f := range rule.Match.Filters {
		if f.ArgumentKindNotAt == nil {
			continue
		}
		if len(f.ArgumentKindNotAt.Kinds) == 0 {
			errs = append(errs, fmt.Sprintf("match.filters[%d].argument_kind_not_at: kinds must not be empty", i))
		}
		for _, k := range f.ArgumentKindNotAt.Kinds {
			if !validNodeKinds[k] {
				errs = append(errs, fmt.Sprintf("match.filters[%d].argument_kind_not_at: unknown node kind %q", i, k))
			}
		}
	}

	errs = append(errs, validateFilterRegexes(rule.Match.Filters, "match.filters")...)
	for i, f := range rule.Match.Filters {
		if f.LHSFlowsToCall != "" {
			if _, err := regexp.Compile(f.LHSFlowsToCall); err != nil {
				errs = append(errs, fmt.Sprintf("match.filters[%d].lhs_flows_to_call: invalid regex: %v", i, err))
			}
		}
		if f.LiteralArgument != nil {
			if f.LiteralArgument.Pattern == "" {
				errs = append(errs, fmt.Sprintf("match.filters[%d].literal_argument: pattern must not be empty", i))
			} else if _, err := regexp.Compile(f.LiteralArgument.Pattern); err != nil {
				errs = append(errs, fmt.Sprintf("match.filters[%d].literal_argument.pattern: invalid regex: %v", i, err))
			}
		}
	}

	if rule.Match.CalleeSuffix && rule.Match.Callee == "" {
		errs = append(errs, "match.callee_suffix: requires a callee")
	}
	// A single-segment callee_suffix ("execute") means "this method on any
	// receiver", which is how a sink rule stops being pinned to one hardcoded
	// variable name: `cursor.execute` missed `cur.execute`, `conn.execute` and
	// `session.execute`, and dvpwa scored 0 across 40 files because its DAOs
	// use `cur`.
	//
	// It is only permitted on a rule that constrains the match with filters.
	// The original ≥2-segment floor existed to stop an unconditional rule from
	// broadening — a bare `eval` suffix rule would fire on any `parser.eval()`
	// regardless of the argument. That risk is real and is kept: what makes
	// the wider match safe is the rule's own gating (typically
	// tainted_argument), not the receiver name.
	if rule.Match.CalleeSuffix && !strings.Contains(rule.Match.Callee, ".") && len(rule.Match.Filters) == 0 {
		errs = append(errs, fmt.Sprintf(
			"match.callee_suffix: single-segment callee %q matches the method on any receiver, "+
				"so it requires filters (e.g. tainted_argument) to stay precise; "+
				"use a dotted callee for an unconditional rule",
			rule.Match.Callee))
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

// validateFilterRegexes compiles the regex-valued filters added for the
// context-aware rules, recursing into `not` sub-patterns. The engine treats a
// regex that fails to compile as "no match", so a typo would otherwise turn a
// positive filter into a rule that never fires and a negative one into a
// no-op, silently.
func validateFilterRegexes(fs []Filter, at string) []string {
	var errs []string
	for i, f := range fs {
		for name, pat := range map[string]string{
			"callee_matches":             f.CalleeMatches,
			"decorator_stack_matches":    f.DecoratorStackMatches,
			"enclosing_function_matches": f.EnclosingFunctionMatches,
			"written_file_matches":       f.WrittenFileMatches,
		} {
			if pat == "" {
				continue
			}
			if _, err := regexp.Compile(pat); err != nil {
				errs = append(errs, fmt.Sprintf("%s[%d].%s: %v", at, i, name, err))
			}
		}
		if f.Not != nil {
			errs = append(errs, validateFilterRegexes(f.Not.Filters, fmt.Sprintf("%s[%d].not.filters", at, i))...)
		}
	}
	return errs
}
