package rules

import "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"

// KwargPattern matches a call's keyword argument by name and value. Name and
// NamePattern are both optional (an empty one imposes no constraint); when both
// are empty the pattern matches on value alone, which — combined with an empty
// ValuePattern that matches anything — lets a rule select an argument purely by
// a name regex (e.g. NamePattern "^on[a-z]+$" for inline HTML event handlers).
type KwargPattern struct {
	Name         string // exact keyword argument name, e.g. "debug" ("" = any)
	NamePattern  string // regex against the argument name, e.g. "^on[a-z]+$" ("" = any)
	ValuePattern string // regex against the argument's value text, e.g. "^True$" ("" = any)
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
	// Kwarg requires a keyword argument matching the KwargPattern (by exact name,
	// name regex, and/or value regex) to appear anywhere in the call's argument
	// list, e.g. debug=True, or any inline HTML on* handler attribute.
	Kwarg *KwargPattern
	// ArgumentIdentifierMatches requires at least one identifier anywhere in the call's
	// argument list to match this regex, e.g. a variable named "password" passed to print().
	ArgumentIdentifierMatches string
	// ArgumentLiteralMatches requires at least one literal anywhere in the call's
	// argument list to match this regex, e.g. "MD5" passed to MessageDigest.getInstance().
	ArgumentLiteralMatches string
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
	Kind   string // IRNode kind to match (e.g. "call")
	Callee string // for call nodes: callee identifier text
	// CalleeSuffix, when true, matches Callee against a call's resolved
	// dotted-chain text as a dot-boundary suffix (e.g. "Response.Write"
	// also matches "context.Response.Write") instead of requiring full
	// equality. Ignored unless Callee has at least one dot — see
	// Validator, which rejects the combination outright rather than
	// silently downgrading it, since a single-segment callee (e.g. "eval")
	// would become dangerously broad under suffix matching.
	CalleeSuffix  bool
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
