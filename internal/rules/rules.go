package rules

import "github.com/zerostrike/scanner/internal/core"

// Filter is a typed constraint on a match pattern.
type Filter struct {
	Not           *MatchPattern
	ArgumentCount *int
	HasAttribute  string
}

// MatchPattern is a typed description of what IR node pattern to find.
// Typed fields prevent map[string]interface{} schema drift.
type MatchPattern struct {
	Kind          string   // IRNode kind to match (e.g. "call")
	Callee        string   // for call nodes: callee identifier text
	Identifier    string   // for identifier nodes: variable name
	Literal       string   // for literal nodes: value (regex allowed)
	LHSIdentifier string   // for assignment nodes: regex match on left-hand-side variable name
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
