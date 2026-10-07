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
	// ValueTainted additionally requires the argument's value to carry taint
	// as a whole object (JS/TS): a tainted identifier, member or call, or an
	// object literal that spreads a tainted value ({...req.body}). A tainted
	// value nested under some other key does not count; that is what makes
	// this a mass-assignment test rather than "anything tainted somewhere".
	ValueTainted bool
}

// Filter is a typed constraint on a match pattern.
// ArgumentKindPattern names one positional argument and a set of IR node
// kinds. A negative Index counts from the end, matching argumentAt.
type ArgumentKindPattern struct {
	Index int
	Kinds []string
}

// ArgumentTextPattern names one positional argument and a regex matched
// against that argument's own expression text (see engine.exprText): a
// literal's unquoted value, an identifier's name, or a dotted member chain
// such as req.body. A negative Index counts from the end.
type ArgumentTextPattern struct {
	Index   int
	Pattern string
}

type Filter struct {
	Not           *MatchPattern
	ArgumentCount *int
	HasAttribute  string
	// TaintedArgument requires at least one of the call's argument identifiers
	// to be present in the file's tainted-variable set (see internal/analyzer/taint).
	TaintedArgument bool
	// TaintedArgumentIndex narrows TaintedArgument to a single positional
	// argument (0-based, excluding the callee). Without it "any argument,
	// anywhere in its subtree" is the only option, which is wrong for any sink
	// where exactly one position is dangerous.
	//
	// The format-string family is the motivating case: string.Format,
	// fmt.Sprintf, String.format, util.format and sprintf are vulnerable when
	// the *format string* is attacker-controlled, not when a substituted value
	// is. Matching any argument makes them fire on the entirely safe
	// logger.info("User: %s", name) idiom — a known imprecision that got worse
	// once function parameters became taint sources. Set this to 0 to mean
	// "only the format string".
	TaintedArgumentIndex *int
	// TaintedArgumentMinIndex narrows TaintedArgument to arguments at this
	// position and after, for sinks whose leading arguments are plumbing
	// rather than data. fmt.Fprintf(w, format, args...) writes the format and
	// every substituted value, so no single TaintedArgumentIndex covers it,
	// but argument 0 is the io.Writer — and because every function parameter
	// is seeded tainted, the unnarrowed rule reported the writer itself and
	// fired on fmt.Fprintf(w, "<h1>OK</h1>"). Ignored when
	// TaintedArgumentIndex is set.
	TaintedArgumentMinIndex *int
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
	// ArgumentKindNotAt suppresses the match when the argument at Index is
	// itself one of the named IR node kinds. The check is on that argument's
	// own kind only, never its descendants.
	//
	// It exists because a sink rule can otherwise flag the very pattern it
	// recommends: setTimeout's message says "pass a function, not a string",
	// and the rule fired on arrow functions. Expressed negatively rather than
	// as an allowlist of permitted kinds because a bare identifier holding a
	// string is a legitimate hit, and enumerating every safe kind would
	// exclude it.
	ArgumentKindNotAt *ArgumentKindPattern

	// RequireRealSource restricts the TaintedArgument/TaintedRHS check to
	// taint with a matched source pattern behind it, rejecting taint that
	// exists only because every function parameter is seeded untrusted (see
	// internal/analyzer/taint.Result.Weak).
	//
	// Set it on sinks whose argument is routinely an ordinary parameter --
	// setTimeout, fetch, RegExp, urlopen. Leave it off where parameter taint
	// is the whole point, such as SQL and command injection, or recall drops.
	RequireRealSource bool

	HasBareExcept bool

	// CalleePattern is a regex matched against the call's callee text as the
	// engine renders it. For JavaScript/TypeScript that rendering keeps every
	// receiver: this.http.get, res.status().send, new RegExp().exec. It lets
	// one rule cover a family of receivers/methods that a single exact or
	// suffix callee cannot (res.send / res.status(500).json / NextResponse.json).
	CalleePattern string
	// CalleeCanonical is a regex matched against the callee with its root
	// identifier replaced by the module it was imported or required from
	// (JS/TS): `const cp = require('child_process'); cp.exec(x)` and
	// `import { exec } from 'node:child_process'; exec(x)` both canonicalize
	// to child_process.exec. A root with no import binding is left as written.
	CalleeCanonical string
	// CalleeResolved requires the callee's root identifier to be bound by an
	// import or require in the same file. It is what keeps a generic name
	// (request, got) from matching a local function of the same name.
	CalleeResolved bool
	// ArgumentMatchesAt requires the positional argument at Index to render
	// to text matching Pattern. The check is on the argument itself, not its
	// subtree.
	ArgumentMatchesAt *ArgumentTextPattern
	// DynamicStringArgumentIndex requires the argument at this index to be a
	// string built at runtime: a template literal with a ${} substitution or
	// a + concatenation. Used where building the string at all is the bug
	// (prisma.$queryRawUnsafe), so no taint is required.
	DynamicStringArgumentIndex *int
	// ArgumentReferencesErrorBinding requires an argument to reference a
	// caught error (JS/TS): the binding of an enclosing catch clause, the
	// first parameter of an enclosing err-first or .catch() callback, or a
	// variable assigned from one in the same function. It matches the
	// binding, not the name: a key or property spelled `error` is not a
	// reference, and neither are err.code / err.status style fields or a
	// comparison such as `err instanceof X`.
	ArgumentReferencesErrorBinding bool

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
