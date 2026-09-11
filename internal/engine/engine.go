package engine

import (
	"context"
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer/taint"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

// MatchResult is a single rule match against an IR node.
type MatchResult struct {
	Rule     *rules.Rule
	Node     *ir.IRNode
	Captures map[string]string
	// TaintedVar is the identifier that satisfied a TaintedArgument or
	// TaintedRHS filter on the matched rule, or "" if the rule matched
	// without any taint-gated filter (the common case).
	TaintedVar string
}

// Project provides cross-file context for multi-file analysis (nil in Sprint 1–2).
type Project struct {
	Root string
}

// RuleIndex is a prebuilt dispatch table enabling O(nodes) matching instead of O(rules × nodes).
// Callee-specific call rules are stored in exactly one of byCallee or
// byCalleeSuffix (never both) to avoid double-matching; all other rules go
// in byKind.
type RuleIndex struct {
	byKind   map[ir.NodeKind][]*rules.Rule
	byCallee map[string][]*rules.Rule
	// byCalleeSuffix holds suffix-match-enabled rules (match.callee_suffix:
	// true in YAML), keyed by the LAST dot-separated segment of the rule's
	// callee (e.g. "Response.Write" -> "Write"). A call's own last segment
	// gives an O(1) shortlist; calleeSuffixMatches verifies the full
	// dot-boundary suffix against only that shortlist, not every rule.
	byCalleeSuffix map[string][]*rules.Rule
}

// BuildIndex groups rules by kind and callee at load time.
// Call once after loading rules; pass the result in MatchContext.Index per file.
func BuildIndex(rs []*rules.Rule) *RuleIndex {
	idx := &RuleIndex{
		byKind:         make(map[ir.NodeKind][]*rules.Rule),
		byCallee:       make(map[string][]*rules.Rule),
		byCalleeSuffix: make(map[string][]*rules.Rule),
	}
	for _, r := range rs {
		// A retired rule loads and validates but must never fire. The
		// lifecycle field was validated from the start (see rules.Validator)
		// and read by nothing, so "retired" was documentation — the rule kept
		// matching. Enforced here rather than in the loader so that rule
		// counts, HashRuleSet, and the rule-listing commands still see the
		// retired rule; only matching skips it.
		if r.Lifecycle == "retired" {
			continue
		}
		kind := ir.NodeKind(r.Match.Kind)
		switch {
		case kind == ir.NodeKindCall && r.Match.Callee != "" && r.Match.CalleeSuffix:
			// A single-segment callee_suffix ("execute") means "this method on
			// any receiver". The ≥2-segment floor used to be enforced here and
			// in the Validator, which left every sink rule pinned to one
			// hardcoded receiver name: `cursor.execute` matched nothing in
			// dvpwa, whose DAOs use `cur`, and nothing on `conn.execute` /
			// `session.execute` / `engine.execute` either. Same shape as
			// ZS-GO-014's `tx.Query` and ZS-GO-002's `db.Query`.
			//
			// calleeSuffixMatches already handles the single-segment case
			// correctly (`.execute` is a dot-boundary suffix of `cur.execute`),
			// so only the index and the Validator needed to stop rejecting it.
			// Precision comes from the rule's own filters — every rule using
			// this is taint-gated, so a non-SQL `task.execute(x)` only fires
			// when x is attacker-controlled.
			last := lastCalleeSegment(r.Match.Callee)
			idx.byCalleeSuffix[last] = append(idx.byCalleeSuffix[last], r)
		case kind == ir.NodeKindCall && r.Match.Callee != "":
			// callee-specific rules go only in byCallee to avoid double-matching
			idx.byCallee[r.Match.Callee] = append(idx.byCallee[r.Match.Callee], r)
		default:
			idx.byKind[kind] = append(idx.byKind[kind], r)
		}
	}
	return idx
}

// lastCalleeSegment returns the final dot-separated segment of a dotted
// callee chain (e.g. "context.Response.Write" -> "Write"), or the whole
// string when it has no dot.
func lastCalleeSegment(s string) string {
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// calleeSuffixMatches reports whether ruleCallee is a dot-boundary suffix of
// callText: either an exact match, or callText ends with "."+ruleCallee.
// Requiring the preceding dot (rather than a bare strings.HasSuffix) is what
// stops "XResponse.Write" from matching rule callee "Response.Write" on raw
// substring grounds — only a real trailing segment boundary counts.
func calleeSuffixMatches(ruleCallee, callText string) bool {
	return callText == ruleCallee || strings.HasSuffix(callText, "."+ruleCallee)
}

// MatchContext bundles everything the engine needs to match rules against one file.
type MatchContext struct {
	Index   *RuleIndex // prebuilt at rule-load time, shared across files
	File    *analyzer.AnalysisResult
	Project *Project
}

// Engine matches rules against an AnalysisResult.
type Engine interface {
	Match(ctx context.Context, mc *MatchContext) ([]MatchResult, error)
}

// New returns the default Engine implementation.
func New() Engine { return &defaultEngine{} }

type defaultEngine struct{}

// Match walks the IR once, dispatching only indexed rules per node kind/callee.
func (e *defaultEngine) Match(_ context.Context, mc *MatchContext) ([]MatchResult, error) {
	if mc == nil || mc.Index == nil || mc.File == nil || mc.File.IR == nil {
		return nil, nil
	}
	taintedVars := mc.File.TaintedVars
	weakVars := mc.File.WeakTaintVars
	var out []MatchResult
	fileLang := mc.File.IR.Language
	// consider evaluates one candidate rule against n.
	//
	// The three index buckets are iterated separately rather than gathered
	// into one candidate slice. Gathering used to start with
	// `candidates := mc.Index.byKind[n.Kind]` and append to it — but that
	// slice aliases the shared rule index's own backing array, so whenever it
	// had spare capacity the append wrote *into the index itself*. Every file
	// in a scan matches against that one index across runtime.NumCPU()
	// goroutines, so workers silently overwrote each other's candidate lists
	// and rules were skipped at random: identical scans of the same 12 files
	// returned anywhere from 6 to 11 of the 11 expected findings. That is the
	// "non-reproducible anomaly" left open in Sprint 25. Never append to a
	// slice read out of Index here. Iterating in place also drops a
	// per-call-node allocation from the hot path.
	consider := func(n *ir.IRNode, r *rules.Rule) {
		// A rule only applies to files of its own declared language — the
		// IR shape (assignment/call/try nodes) is language-agnostic, so
		// e.g. a Python "hardcoded credential" rule would otherwise also
		// match an identical-looking assignment in a Go or C# file.
		if r.Language != fileLang {
			return
		}
		if matchNode(r.Match, n, taintedVars, weakVars, fileLang) {
			out = append(out, MatchResult{Rule: r, Node: n, TaintedVar: taintedIdentifierFor(r.Match, n, taintedVars, fileLang)})
		}
	}

	ir.Walk(mc.File.IR.Root, func(n *ir.IRNode) bool {
		for _, r := range mc.Index.byKind[n.Kind] {
			consider(n, r)
		}
		if n.Kind == ir.NodeKindCall {
			text := calleeText(n)
			for _, r := range mc.Index.byCallee[text] {
				consider(n, r)
			}
			for _, r := range mc.Index.byCalleeSuffix[lastCalleeSegment(text)] {
				if calleeSuffixMatches(r.Match.Callee, text) {
					consider(n, r)
				}
			}
		}
		return true
	})
	return out, nil
}

// calleeText extracts the callee name from a call node.
// Handles plain calls (eval) and attribute calls (os.system, pickle.loads).
func calleeText(n *ir.IRNode) string {
	for _, c := range n.Children {
		switch c.Kind {
		case ir.NodeKindIdentifier:
			if c.Text != "" {
				return c.Text
			}
		case ir.NodeKindAttribute:
			if t := attributeText(c); t != "" {
				return t
			}
		}
	}
	return ""
}

// attributeText resolves a dotted attribute chain (a.b.c) to its full text.
// The object side of a 3+-segment chain is itself a nested NodeKindAttribute
// (e.g. urllib.request.urlopen parses as attribute(attribute(urllib,
// request), urlopen)), so this recurses rather than only reading direct
// Identifier children — a 2-segment chain (os.system) has both parts as
// direct Identifier children already and is unaffected.
func attributeText(n *ir.IRNode) string {
	var parts []string
	for _, c := range n.Children {
		switch c.Kind {
		case ir.NodeKindIdentifier:
			if c.Text != "" {
				parts = append(parts, c.Text)
			}
		case ir.NodeKindAttribute:
			if t := attributeText(c); t != "" {
				parts = append(parts, t)
			}
		}
	}
	return strings.Join(parts, ".")
}

// matchNode checks whether a node satisfies the match pattern.
// Callee matching is already handled by the index; matchNode covers
// Identifier, Literal, and Filter constraints.
func matchNode(pattern rules.MatchPattern, n *ir.IRNode, taintedVars, weak map[string]bool, lang core.Language) bool {
	if ir.NodeKind(pattern.Kind) != n.Kind {
		return false
	}
	if pattern.Identifier != "" && n.Text != pattern.Identifier {
		return false
	}
	if pattern.Literal != "" {
		matched, err := regexp.MatchString(pattern.Literal, n.Text)
		if err != nil || !matched {
			return false
		}
	}
	if pattern.LHSIdentifier != "" {
		lhs, _ := n.Attrs["lhs"].(string)
		matched, err := regexp.MatchString(pattern.LHSIdentifier, lhs)
		if err != nil || !matched {
			return false
		}
	}
	if pattern.RHSLiteral != "" {
		rhs, _ := n.Attrs["rhs"].(string)
		matched, err := regexp.MatchString(pattern.RHSLiteral, rhs)
		if err != nil || !matched {
			return false
		}
	}
	for _, f := range pattern.Filters {
		if !evalFilter(f, n, taintedVars, weak, lang) {
			return false
		}
	}
	return true
}

func evalFilter(f rules.Filter, n *ir.IRNode, taintedVars, weak map[string]bool, lang core.Language) bool {
	if f.ArgumentCount != nil {
		ac, _ := n.Attrs["argument_count"].(int)
		if ac != *f.ArgumentCount {
			return false
		}
	}
	if f.HasAttribute != "" {
		found := false
		for _, c := range n.Children {
			if c.Kind == ir.NodeKindAttribute && strings.Contains(attributeText(c), f.HasAttribute) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.TaintedArgument {
		isTainted := func(a *ir.IRNode) bool {
			if a.Kind == ir.NodeKindIdentifier && taintedVars[a.Text] {
				// require_real_source rejects taint that exists only because
				// every function parameter is seeded untrusted. See
				// taint.Result.Weak: without this, any helper that takes an
				// argument looks attacker-controlled, which is what made
				// setTimeout/fetch/RegExp fire on ordinary React code.
				return !f.RequireRealSource || !weak[a.Text]
			}
			// An inline source expression (sink(req.query.x)) matched a real
			// source pattern by definition, so it is never weak.
			return isDirectSourceExpression(a, lang)
		}
		scan := anyArgument
		switch {
		case f.TaintedArgumentIndex != nil:
			i := *f.TaintedArgumentIndex
			scan = func(n *ir.IRNode, pred func(*ir.IRNode) bool) bool {
				return argumentAt(n, i, pred)
			}
		case f.TaintedArgumentMinIndex != nil:
			m := *f.TaintedArgumentMinIndex
			scan = func(n *ir.IRNode, pred func(*ir.IRNode) bool) bool {
				return argumentsFrom(n, m, pred)
			}
		}
		if !scan(n, isTainted) {
			return false
		}
	}
	if f.Kwarg != nil {
		if !anyArgument(n, func(a *ir.IRNode) bool {
			if a.Kind != ir.NodeKindKeywordArg {
				return false
			}
			name, _ := a.Attrs["kwarg_name"].(string)
			if f.Kwarg.Name != "" && name != f.Kwarg.Name {
				return false
			}
			if f.Kwarg.NamePattern != "" {
				if m, err := regexp.MatchString(f.Kwarg.NamePattern, name); err != nil || !m {
					return false
				}
			}
			value, _ := a.Attrs["kwarg_value"].(string)
			matched, err := regexp.MatchString(f.Kwarg.ValuePattern, value)
			return err == nil && matched
		}) {
			return false
		}
	}
	if f.ArgumentIdentifierMatches != "" {
		if !anyArgument(n, func(a *ir.IRNode) bool {
			if a.Kind != ir.NodeKindIdentifier {
				return false
			}
			matched, err := regexp.MatchString(f.ArgumentIdentifierMatches, a.Text)
			return err == nil && matched
		}) {
			return false
		}
	}
	if f.ArgumentLiteralMatches != "" {
		if !anyArgument(n, func(a *ir.IRNode) bool {
			if a.Kind != ir.NodeKindLiteral {
				return false
			}
			matched, err := regexp.MatchString(f.ArgumentLiteralMatches, a.Text)
			return err == nil && matched
		}) {
			return false
		}
	}
	if f.ArgumentKindNotAt != nil {
		if !argumentKindAllowed(n, *f.ArgumentKindNotAt) {
			return false
		}
	}
	if f.TaintedRHS {
		if !rhsIsTainted(n, taintedVars, weak, f.RequireRealSource, lang) {
			return false
		}
	}
	if f.HasBareExcept {
		if !anyExceptHandler(n, func(h ir.ExceptHandler) bool { return h.IsBare }) {
			return false
		}
	}
	if f.HasEmptyExceptHandler {
		if !anyExceptHandler(n, func(h ir.ExceptHandler) bool { return h.IsEmptyBody }) {
			return false
		}
	}
	if f.Not != nil {
		if matchNode(*f.Not, n, taintedVars, weak, lang) {
			return false
		}
	}
	return true
}

// anyExceptHandler reports whether any except clause recorded on a try_statement
// node's Attrs["except_handlers"] satisfies pred.
func anyExceptHandler(n *ir.IRNode, pred func(ir.ExceptHandler) bool) bool {
	handlers, _ := n.Attrs["except_handlers"].([]ir.ExceptHandler)
	for _, h := range handlers {
		if pred(h) {
			return true
		}
	}
	return false
}

// rhsIsTainted reports whether an assignment node's right-hand-side subtree
// (its last child — see the Python/JS/TS grammars' left, '=', right shape)
// contains an identifier present in taintedVars, or a source pattern matched
// directly inline (element.innerHTML = req.body.x, with no intervening
// assignment to a named variable — see isDirectSourceExpression).
func rhsIsTainted(n *ir.IRNode, taintedVars, weak map[string]bool, requireRealSource bool, lang core.Language) bool {
	if n.Kind != ir.NodeKindAssignment || len(n.Children) == 0 {
		return false
	}
	// strongly reports whether an identifier's taint counts under this
	// filter's require_real_source setting — see taint.Result.Weak.
	strongly := func(name string) bool {
		return taintedVars[name] && (!requireRealSource || !weak[name])
	}
	rhs := n.Children[len(n.Children)-1]
	if rhs.Kind == ir.NodeKindIdentifier && strongly(rhs.Text) {
		return true
	}
	if isDirectSourceExpression(rhs, lang) {
		return true
	}
	for _, d := range ir.Descendants(rhs) {
		if d.Kind == ir.NodeKindIdentifier && strongly(d.Text) {
			return true
		}
		if isDirectSourceExpression(d, lang) {
			return true
		}
	}
	return false
}

// isDirectSourceExpression reports whether n's own text (not its
// descendants — callers walk those separately, e.g. via anyArgument/
// ir.Descendants) matches one of lang's taint source patterns directly.
// This recognizes a source used inline (sink(req.body.x)) in addition to
// the assignment-based taintedVars propagation the taint pass already
// handles (const v = req.body.x; sink(v)) — see taint.IsSource's doc
// comment for why the assignment-based pass alone misses this.
func isDirectSourceExpression(n *ir.IRNode, lang core.Language) bool {
	switch n.Kind {
	case ir.NodeKindCall:
		// Source patterns like "request.getParameter(" or "os.Getenv("
		// include the trailing paren — the assignment-based check sees it
		// naturally via raw RHS source text, so calleeText needs it added
		// back explicitly here.
		return taint.IsSource(lang, calleeText(n)+"(")
	case ir.NodeKindAttribute:
		return taint.IsSource(lang, attributeText(n))
	case ir.NodeKindIdentifier:
		return taint.IsSource(lang, n.Text)
	default:
		return false
	}
}

// anyArgument reports whether any node in a call's argument list (everything
// after the callee/function child) satisfies pred. Returns false for non-call
// nodes or calls with no argument list child.
// argumentNodes returns a call's real positional arguments, in order.
//
// Children[0] is the callee, but Children[1:] is not simply the argument list:
// some builders keep the grammar's punctuation tokens as Unknown children.
// Java lowers String.format("a" + b) to four children — the callee attribute,
// "(", the binary_op, ")" — so naive Children[1+i] indexing would treat the
// open paren as argument 0. anyArgument never noticed because a paren is never
// a tainted identifier, but positional matching cannot ignore it.
func argumentNodes(n *ir.IRNode) []*ir.IRNode {
	if n.Kind != ir.NodeKindCall || len(n.Children) < 2 {
		return nil
	}
	// Locate the argument_list wherever it sits rather than assuming it
	// directly follows the callee. Three shapes exist:
	//
	//   method call (Go, C#, JS/TS, PHP): [callee, argument_list]
	//   constructor (C#):                 ["new", TypeName, argument_list]
	//   Java:                             [callee, "(", arg, ",", arg, ")"]
	//
	// Assuming Children[1] was the argument list made a C# constructor's TYPE
	// NAME argument 0, so pinning `new SqliteDataAdapter(sql, conn)` to
	// argument 0 matched the type identifier — never tainted — and silently
	// dropped 21 real SQL injections while the corpus stayed green.
	candidates := n.Children[1:]
	for _, c := range n.Children {
		if isArgumentList(c) {
			candidates = c.Children
			break
		}
	}
	out := make([]*ir.IRNode, 0, len(candidates))
	for _, c := range candidates {
		// Drop only the grammar's punctuation. Emphatically NOT empty-text
		// nodes: C# and PHP lower a string-concatenation argument to an
		// Unknown node whose own Text is empty, so treating "" as punctuation
		// silently deletes the real argument.
		if c.Kind == ir.NodeKindUnknown {
			switch strings.TrimSpace(c.Text) {
			case "(", ")", ",":
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// isArgumentList reports whether c is a builder's unnamed argument_list
// wrapper. Identified by its delimiters rather than by empty text, since a
// real argument can also be an empty-text Unknown node.
func isArgumentList(c *ir.IRNode) bool {
	if c.Kind != ir.NodeKindUnknown || len(c.Children) < 2 {
		return false
	}
	return strings.TrimSpace(c.Children[0].Text) == "(" &&
		strings.TrimSpace(c.Children[len(c.Children)-1].Text) == ")"
}

// argumentAt applies pred to the i-th positional argument (0-based) and its
// subtree. Returns false when the call has fewer arguments than that — a rule
// asking about argument 2 of a one-argument call simply does not match.
func argumentAt(n *ir.IRNode, i int, pred func(*ir.IRNode) bool) bool {
	args := argumentNodes(n)
	// A negative index counts from the end, so -1 is the last argument. This
	// is what makes overloaded sinks expressible: pg_query has both
	// pg_query($query) and pg_query($conn, $query), and mysqli_query is
	// mysqli_query($link, $query) — the query is the last argument in every
	// form, but no single non-negative index describes it.
	if i < 0 {
		i += len(args)
	}
	if i < 0 || i >= len(args) {
		return false
	}
	if pred(args[i]) {
		return true
	}
	for _, d := range ir.Descendants(args[i]) {
		if pred(d) {
			return true
		}
	}
	return false
}

// argumentsFrom applies pred to every positional argument from index min
// onward, and their subtrees. It exists for sinks whose leading arguments are
// plumbing rather than data: fmt.Fprintf(w, format, args...) writes the format
// and every substituted value to w, so no single argumentAt index describes
// the danger, while plain anyArgument matched the io.Writer itself — and since
// every handler parameter is seeded tainted, fmt.Fprintf(w, "<h1>OK</h1>")
// reported constant output as XSS.
func argumentsFrom(n *ir.IRNode, min int, pred func(*ir.IRNode) bool) bool {
	args := argumentNodes(n)
	if min < 0 || min >= len(args) {
		return false
	}
	for _, argRoot := range args[min:] {
		if pred(argRoot) {
			return true
		}
		for _, d := range ir.Descendants(argRoot) {
			if pred(d) {
				return true
			}
		}
	}
	return false
}

func anyArgument(n *ir.IRNode, pred func(*ir.IRNode) bool) bool {
	if n.Kind != ir.NodeKindCall || len(n.Children) < 2 {
		return false
	}
	for _, argRoot := range n.Children[1:] {
		if pred(argRoot) {
			return true
		}
		for _, d := range ir.Descendants(argRoot) {
			if pred(d) {
				return true
			}
		}
	}
	return false
}

// taintedIdentifierFor inspects pattern's top-level filters (not recursing
// into a Filter.Not sub-pattern, since polarity is inverted there and "which
// identifier is tainted" isn't meaningful for a negated match) for a
// TaintedArgument or TaintedRHS filter, and if found, returns the actual
// tainted identifier's text that satisfied it. Returns "" when the rule
// matched without using either filter — the common case for most rules.
func taintedIdentifierFor(pattern rules.MatchPattern, n *ir.IRNode, taintedVars map[string]bool, lang core.Language) string {
	for _, f := range pattern.Filters {
		if f.TaintedArgument {
			if id := firstTaintedArgument(n, taintedVars, lang); id != "" {
				return id
			}
		}
		if f.TaintedRHS {
			if id := firstTaintedRHSIdentifier(n, taintedVars, lang); id != "" {
				return id
			}
		}
	}
	return ""
}

// firstTaintedArgument returns the text of the first tainted identifier found
// in a call's argument list, or — when no named tainted variable is found —
// the text of the first node matching a source pattern directly inline (see
// isDirectSourceExpression). Returns "" if neither is found. Same traversal
// shape as anyArgument, kept separate since evalFilter's anyArgument-based
// check only needs a bool on the hot matching path.
func firstTaintedArgument(n *ir.IRNode, taintedVars map[string]bool, lang core.Language) string {
	if n.Kind != ir.NodeKindCall || len(n.Children) < 2 {
		return ""
	}
	for _, argRoot := range n.Children[1:] {
		if argRoot.Kind == ir.NodeKindIdentifier && taintedVars[argRoot.Text] {
			return argRoot.Text
		}
		for _, d := range ir.Descendants(argRoot) {
			if d.Kind == ir.NodeKindIdentifier && taintedVars[d.Text] {
				return d.Text
			}
		}
	}
	for _, argRoot := range n.Children[1:] {
		if isDirectSourceExpression(argRoot, lang) {
			return sourceExpressionText(argRoot)
		}
		for _, d := range ir.Descendants(argRoot) {
			if isDirectSourceExpression(d, lang) {
				return sourceExpressionText(d)
			}
		}
	}
	return ""
}

// sourceExpressionText returns the best-effort display text for a node that
// isDirectSourceExpression matched, for the MatchResult.TaintedVar report
// field — the same text isDirectSourceExpression tested against the source
// patterns (with the call form's trailing "(" omitted, since it's only
// needed for the regex match, not for display).
func sourceExpressionText(n *ir.IRNode) string {
	switch n.Kind {
	case ir.NodeKindCall:
		return calleeText(n)
	case ir.NodeKindAttribute:
		return attributeText(n)
	default:
		return n.Text
	}
}

// firstTaintedRHSIdentifier returns the text of the tainted identifier in an
// assignment's right-hand-side subtree, or — when no named tainted variable
// is found — the text of the first node matching a source pattern directly
// inline (see isDirectSourceExpression). Returns "" if neither is found.
// Same traversal shape as rhsIsTainted, kept separate since evalFilter's
// rhsIsTainted-based check only needs a bool on the hot matching path.
func firstTaintedRHSIdentifier(n *ir.IRNode, taintedVars map[string]bool, lang core.Language) string {
	if n.Kind != ir.NodeKindAssignment || len(n.Children) == 0 {
		return ""
	}
	rhs := n.Children[len(n.Children)-1]
	if rhs.Kind == ir.NodeKindIdentifier && taintedVars[rhs.Text] {
		return rhs.Text
	}
	for _, d := range ir.Descendants(rhs) {
		if d.Kind == ir.NodeKindIdentifier && taintedVars[d.Text] {
			return d.Text
		}
	}
	if isDirectSourceExpression(rhs, lang) {
		return sourceExpressionText(rhs)
	}
	for _, d := range ir.Descendants(rhs) {
		if isDirectSourceExpression(d, lang) {
			return sourceExpressionText(d)
		}
	}
	return ""
}

// argumentKindAllowed reports whether the positional argument named by spec is
// NOT one of spec.Kinds - i.e. whether the match survives the filter.
//
// The kind check is on the argument node itself and deliberately does not walk
// descendants, unlike argumentAt. That difference is the entire point: an
// arrow function passed to setTimeout contains identifiers and calls in its
// body, so a descendant walk would find almost any kind inside it and the
// filter would never exclude anything.
//
// A call with no such argument passes: "argument 0 is not a function" is
// vacuously true when there is no argument 0, and the rule's other filters
// are what decide those cases.
func argumentKindAllowed(n *ir.IRNode, spec rules.ArgumentKindPattern) bool {
	args := argumentNodes(n)
	i := spec.Index
	if i < 0 {
		i += len(args)
	}
	if i < 0 || i >= len(args) {
		return true
	}
	for _, k := range spec.Kinds {
		if args[i].Kind == ir.NodeKind(k) {
			return false
		}
	}
	return true
}
