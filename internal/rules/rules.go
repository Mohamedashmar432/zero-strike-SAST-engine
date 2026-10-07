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
// ArgumentKindPattern names one positional argument and a set of IR node
// kinds. A negative Index counts from the end, matching argumentAt.
type ArgumentKindPattern struct {
	Index int
	Kinds []string
}

// LiteralArgumentPattern requires the positional argument at Index (0-based,
// negative counts from the end) to BE a literal -- the argument node itself,
// not something inside it -- whose text matches Pattern.
type LiteralArgumentPattern struct {
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

	// CalleeMatches requires a call's callee text to match this regex. It is
	// tested against both the callee as written and, for Python, its
	// import-canonicalized form (md5 -> hashlib.md5), so one rule can cover a
	// family of callees (hashlib.md5|sha1|sha256) that would otherwise need
	// one rule file per exact callee.
	CalleeMatches string
	// DecoratorStackMatches requires one decorator on the same definition to
	// match this regex. On a decorator node it reads the decorator's own
	// stack ("decorator_stack"); on a function/class node its "decorators".
	// Used negatively to skip csrf_exempt views that also carry require_GET.
	DecoratorStackMatches string
	// EnclosingFunctionMatches requires the nearest enclosing function's name
	// to match this regex, e.g. a random-module call inside generate_token().
	EnclosingFunctionMatches string
	// ArgumentNotConstant suppresses the match when the positional argument
	// at this index is a compile-time constant. In every language a literal
	// with no interpolated expression is constant (a template literal with a
	// ${} substitution is not). Python additionally folds paths: __file__,
	// and os.path.join/dirname/abspath, pathlib.Path and "/" joins built only
	// from constants, followed through local variables whose every
	// assignment is itself constant.
	ArgumentNotConstant *int
	// WrittenFileMatches requires a file-write call (f.write(x),
	// Path(p).write_text(x)) to write to a handle whose path matches this
	// regex. The path is resolved from the receiver: an open(path, mode) /
	// Path(path) call, directly or through a local variable or `with ... as`
	// binding. Unknown path segments render as "*", so
	// os.path.join(BASE, f"templates/{id}.html") reads as "*/templates/*.html".
	// A handle opened read-only never matches.
	WrittenFileMatches string

	// LiteralArgument requires the argument at a position to be a literal
	// matching a regex: a hardcoded key passed straight to jwt.encode or
	// createHmac. Unlike ArgumentLiteralMatches it is positional and does not
	// look inside the argument, so jwt.encode({'role': 'admin'}, key) does not
	// match on the payload's literals.
	LiteralArgument *LiteralArgumentPattern

	// LHSFlowsToCall requires the assignment's target variable to be passed,
	// within the same function (or the file, for a top-level assignment), as
	// an argument to a call whose callee chain matches this regex. The chain
	// includes calls in the receiver, so createHash('sha256').update(secret)
	// counts as reaching createHash. It separates a hardcoded value that is
	// key material (it feeds a cipher, HMAC or JWT signer: CWE-321) from one
	// that is a credential (CWE-798).
	LHSFlowsToCall string

	HasBareExcept bool
	// HasEmptyExceptHandler requires a try_statement node to contain at least one
	// except clause whose body is just "pass" (see ir.ExceptHandler.IsEmptyBody).
	HasEmptyExceptHandler bool

	// ExceptHandler requires a try_statement node to have at least one except
	// / catch clause satisfying every constraint set on the pattern. Unlike
	// HasBareExcept and HasEmptyExceptHandler, which each test one property
	// of "any" clause, it tests all properties against the SAME clause --
	// "is there an empty handler that is also broad" cannot be expressed as
	// two independent any-clause checks.
	ExceptHandler *ExceptHandlerPattern

	// TryBodyCallsOnly matches a try_statement whose protected block makes at
	// least one call and every call's callee text matches this regex. Used
	// negated: a try that only parses or converts (JSON.parse, parseInt, new
	// URL) has an obvious, deliberate fallback when it fails.
	TryBodyCallsOnly string

	// ContextIdentifierMatches requires the name the matched expression's
	// value is bound to -- the assignment target, the object key, or for a
	// returned value the enclosing function's name -- to match this regex.
	// The name is normalised to lower snake_case first (sessionToken ->
	// session_token), so a pattern can anchor on word boundaries with
	// (^|_)token(_|$) instead of matching substrings. The climb stops at the
	// enclosing statement: Math.random() used for a captcha operand or a
	// shuffle never reaches a security-named binding.
	ContextIdentifierMatches string

	// EnclosingFunctionCalls requires the innermost enclosing function (or the
	// module, for top-level code) to contain a call whose callee text matches
	// this regex. Used negated, e.g. jwt.decode is only a missing-verification
	// bug when nothing in the same function verifies the token.
	EnclosingFunctionCalls string

	// EnclosingFunctionMentions requires the innermost enclosing function (or
	// module) to contain an identifier or literal matching this regex. Used
	// negated to recognise intent, e.g. an MD5 digest built inside a
	// "checksum" task is an integrity label, not a security control.
	EnclosingFunctionMentions string

	// ArgumentLiteralIndex narrows ArgumentLiteralMatches to one positional
	// argument (negative counts from the end), e.g. "the program spawned is a
	// shell" rather than "some literal somewhere in the argv is 'sh'".
	ArgumentLiteralIndex *int

	// AnyOf passes when at least one of the listed filters passes. Each entry
	// is a full Filter, so the keys inside one entry are ANDed together. It
	// exists because a rule's filter list is a conjunction, and sinks like
	// child_process.spawn are dangerous under any of several conditions
	// (tainted program, shell: true, or a shell interpreter with -c).
	AnyOf []Filter
}

// ExceptHandlerPattern constrains one except/catch clause. Every non-nil field
// must hold for the same clause. See ir.ExceptHandler for the recorded
// properties.
type ExceptHandlerPattern struct {
	// Bare: the clause names no exception type (Python "except:").
	Bare *bool
	// Empty: the handler body does nothing (Python "pass", JS "{}" or a
	// body holding only comments).
	Empty *bool
	// Broad: the clause catches everything -- bare, a JS catch (untyped), or
	// a catch-all type such as Exception, BaseException or Throwable. A
	// handler for FileNotFoundError or KeyError is narrow: swallowing it is
	// ordinary EAFP control flow, not a hidden failure.
	Broad *bool
	// Commented: the handler body contains a comment. An empty handler that
	// carries "// ignore" or "# best effort" documents a deliberate choice.
	Commented *bool
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
	// Tier is the output tier of this rule's findings: security (the default
	// when empty), hardening or quality. Non-security tiers are left out of
	// default scan output and counted in the report instead; --include-hardening
	// brings them back. See core.Tier.
	Tier core.Tier
	// OncePerFile reports only the first match of this rule in each file. Set
	// it on rules that describe a file- or app-wide policy rather than a
	// per-call defect (an app-wide cors() default registered on several
	// routes is one policy, not one finding per route).
	OncePerFile bool
	// SkipContexts lists execution contexts the rule does not apply to.
	// "browser" covers inline <script> blocks in HTML, Angular modules
	// (importing @angular/core), "use client" React modules and files under
	// a frontend/ source root: a server-side sink such as log forging into
	// console.log has no meaning in a browser's devtools console.
	SkipContexts []string
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
