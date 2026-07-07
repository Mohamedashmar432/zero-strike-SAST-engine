package rules

import "github.com/zerostrike/scanner/internal/core"

// KwargPattern matches a call's keyword argument by name and value.
type KwargPattern struct {
	Name         string // keyword argument name, e.g. "debug"
	ValuePattern string // regex against the argument's value text, e.g. "^True$"
}

// Filter is a typed constraint on a match pattern.
type Filter struct {
	Not           *MatchPattern
	ArgumentCount *int
	HasAttribute  string
	// TaintedArgument requires at least one of the call's argument identifiers
	// to be present in the file's tainted-variable set (see internal/analyzer/taint).
	TaintedArgument bool
	// TaintedRHS requires an assignment node's right-hand-side subtree to contain
	// an identifier present in the file's tainted-variable set. Use for
	// assignment-based sinks (e.g. element.innerHTML = ...) where TaintedArgument
	// (call-argument-only) doesn't apply.
	TaintedRHS bool
	// Kwarg requires a keyword argument matching Name whose value matches ValuePattern
	// to appear anywhere in the call's argument list, e.g. debug=True.
	Kwarg *KwargPattern
	// ArgumentIdentifierMatches requires at least one identifier anywhere in the call's
	// argument list to match this regex, e.g. a variable named "password" passed to print().
	ArgumentIdentifierMatches string
	// HasBareExcept requires a try_statement node to contain at least one bare
	// "except:" clause (see ir.ExceptHandler.IsBare).
	HasBareExcept bool
	// HasEmptyExceptHandler requires a try_statement node to contain at least one
	// except clause whose body is just "pass" (see ir.ExceptHandler.IsEmptyBody).
	HasEmptyExceptHandler bool
}

// MatchPattern is a typed description of what IR node pattern to find.
// Typed fields prevent map[string]interface{} schema drift.
type MatchPattern struct {
	Kind          string // IRNode kind to match (e.g. "call")
	Callee        string // for call nodes: callee identifier text
	Identifier    string // for identifier nodes: variable name
	Literal       string // for literal nodes: value (regex allowed)
	LHSIdentifier string // for assignment nodes: regex match on left-hand-side variable name
	RHSLiteral    string // for assignment nodes: regex match on right-hand-side text
	Filters       []Filter
}

// Rule is a parsed and validated security rule.
type Rule struct {
	ID            string
	Name          string
	Version       string
	Language      core.Language
	Category      string
	Severity      core.Severity
	Confidence    core.Confidence
	Description   string
	Message       string
	Tags          []string
	CWE           []string
	OWASP         []string
	References    []string
	Match         MatchPattern
	FixSuggestion string
	Rationale     string
	// Lifecycle is one of draft, validated, released, retired (see Validator).
	Lifecycle string
}

// Registry provides rule lookup by language and category.
type Registry interface {
	Add(rule *Rule)
	ByLanguage(lang core.Language) []*Rule
	ByCategory(category string) []*Rule
	ByTag(tag string) []*Rule
	All() []*Rule
}

// Loader reads Rule definitions from YAML files or embedded content.
type Loader interface {
	Load(source string) ([]*Rule, error)
	LoadDir(dir string) ([]*Rule, error)
}

// Validator checks Rule definitions for schema correctness.
type Validator interface {
	Validate(rule *Rule) []string // returns validation error messages
}
