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
	// Browser marks code that runs in a browser rather than on a server: an
	// inline <script> in an HTML document, an Angular or "use client" module,
	// or a file under a frontend/ source root (see IsBrowserContext). Rules
	// listing "browser" in SkipContexts do not run against it.
	Browser bool
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
	fileLang := mc.File.IR.Language
	fc := newFileCtx(mc.File.IR, taintedVars, mc.File.WeakTaintVars)
	var out []MatchResult
	// reported tracks rules with OncePerFile that have already matched here.
	reported := map[*rules.Rule]bool{}
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
		if mc.Browser && skipsContext(r, "browser") {
			return
		}
		if r.OncePerFile && reported[r] {
			return
		}
		if matchNode(r.Match, n, fc) {
			if r.OncePerFile {
				reported[r] = true
			}
			out = append(out, MatchResult{Rule: r, Node: n, TaintedVar: taintedIdentifierFor(r.Match, n, taintedVars, fileLang)})
		}
	}

	ir.Walk(mc.File.IR.Root, func(n *ir.IRNode) bool {
		for _, r := range mc.Index.byKind[n.Kind] {
			consider(n, r)
		}
		if n.Kind == ir.NodeKindCall {
			// text is the callee as written; canon resolves its first
			// segment through the file's import table (Python only, see
			// canonicalAlias), so `from hashlib import md5; md5(x)` reaches
			// a rule written against hashlib.md5. Both forms are offered:
			// rules written against a conventional alias (ET.fromstring)
			// must keep matching the written text.
			text := fc.callee(n)
			canon := fc.canonicalAlias(text)
			for _, r := range mc.Index.byCallee[text] {
				consider(n, r)
			}
			if canon != text {
				for _, r := range mc.Index.byCallee[canon] {
					consider(n, r)
				}
			}
			suffixRule := func(r *rules.Rule) {
				if calleeSuffixMatches(r.Match.Callee, text) || (canon != text && calleeSuffixMatches(r.Match.Callee, canon)) {
					consider(n, r)
				}
			}
			last, canonLast := lastCalleeSegment(text), lastCalleeSegment(canon)
			for _, r := range mc.Index.byCalleeSuffix[last] {
				suffixRule(r)
			}
			if canonLast != last {
				for _, r := range mc.Index.byCalleeSuffix[canonLast] {
					suffixRule(r)
				}
			}
		}
		return true
	})
	return out, nil
}

// calleeTextFor extracts the callee text of a call node in lang's rendering.
// JavaScript and TypeScript use jsCalleeText, which keeps non-identifier
// receivers as placeholder segments (this.http.get, res.status().send); every
// other language keeps the historical calleeText rendering.
func calleeTextFor(n *ir.IRNode, lang core.Language) string {
	if isJSLike(lang) {
		return jsCalleeText(n, nil)
	}
	return calleeText(n)
}

// attributeTextFor is calleeTextFor's counterpart for a bare attribute node.
func attributeTextFor(n *ir.IRNode, lang core.Language) string {
	if isJSLike(lang) {
		return jsExprText(n, nil)
	}
	return attributeText(n)
}

// calleeText extracts the callee name from a call node.
// Handles plain calls (eval) and attribute calls (os.system, pickle.loads).
//
// For JavaScript/TypeScript use calleeTextFor: this rendering drops every
// child that is not an Identifier or Attribute, so `this.http.get` collapsed
// to `http.get` and `res.status(500).send` to `send`.
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
func matchNode(pattern rules.MatchPattern, n *ir.IRNode, fc *fileCtx) bool {
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
		if n.Kind == ir.NodeKindReturn {
			// On a return node rhs_literal matches the returned expression,
			// the same "value being produced" an assignment's RHS is.
			rhs, _ = n.Attrs["return_expr"].(string)
		}
		matched, err := regexp.MatchString(pattern.RHSLiteral, rhs)
		if err != nil || !matched {
			return false
		}
	}
	for _, f := range pattern.Filters {
		if !evalFilter(f, n, fc) {
			return false
		}
	}
	return true
}

func evalFilter(f rules.Filter, n *ir.IRNode, fc *fileCtx) bool {
	taintedVars, weak, lang := fc.tainted, fc.weak, fc.lang
	if !evalContextFilters(f, n, fc) {
		return false
	}
	if f.ArgumentCount != nil {
		ac, _ := n.Attrs["argument_count"].(int)
		if ac != *f.ArgumentCount {
			return false
		}
	}
	if f.HasAttribute != "" {
		found := false
		for _, c := range n.Children {
			if c.Kind == ir.NodeKindAttribute && strings.Contains(attributeTextFor(c, lang), f.HasAttribute) {
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
		pred := func(a *ir.IRNode) bool {
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
			if err != nil || !matched {
				return false
			}
			return !f.Kwarg.ValueTainted || fc.kwargValueTainted(a)
		}
		// JS/TS: an options object is as often a named local as an inline
		// literal (const opts = {noent: true}; parseXml(data, opts)). Look
		// through an identifier argument to its same-file object initializer.
		if !anyArgument(n, pred) && !fc.anyResolvedObjectArgument(n, pred) {
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
		pred := func(a *ir.IRNode) bool {
			value, ok := literalValue(a, fc.consts)
			if !ok {
				return false
			}
			matched, err := regexp.MatchString(f.ArgumentLiteralMatches, value)
			return err == nil && matched
		}
		if f.ArgumentLiteralIndex != nil {
			if !argumentAt(n, *f.ArgumentLiteralIndex, pred) {
				return false
			}
		} else if !anyArgument(n, pred) {
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
	if !fc.evalJSFilters(f, n) {
		return false
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
	if f.LiteralArgument != nil {
		if !literalArgumentMatches(n, *f.LiteralArgument) {
			return false
		}
	}
	if f.LHSFlowsToCall != "" {
		if !lhsFlowsToCall(n, cachedRegexp(f.LHSFlowsToCall)) {
			return false
		}
	}
	if f.ExceptHandler != nil {
		if !anyExceptHandler(n, func(h ir.ExceptHandler) bool { return exceptHandlerMatches(*f.ExceptHandler, h) }) {
			return false
		}
	}
	if f.TryBodyCallsOnly != "" {
		if !tryBodyCallsOnly(n, f.TryBodyCallsOnly) {
			return false
		}
	}
	if f.ContextIdentifierMatches != "" {
		re := cachedRegexp(f.ContextIdentifierMatches)
		if re == nil {
			return false
		}
		found := false
		for _, name := range contextNames(n) {
			if re.MatchString(snakeCase(name)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.EnclosingFunctionCalls != "" {
		re := cachedRegexp(f.EnclosingFunctionCalls)
		if re == nil {
			return false
		}
		if !scopeContains(n, func(d *ir.IRNode) bool {
			return d.Kind == ir.NodeKindCall && re.MatchString(calleeText(d))
		}) {
			return false
		}
	}
	if f.EnclosingFunctionMentions != "" {
		re := cachedRegexp(f.EnclosingFunctionMentions)
		if re == nil {
			return false
		}
		if !scopeContains(n, func(d *ir.IRNode) bool {
			return (d.Kind == ir.NodeKindIdentifier || d.Kind == ir.NodeKindLiteral) && re.MatchString(d.Text)
		}) {
			return false
		}
	}
	if f.AnyOf != nil {
		passed := false
		for _, sub := range f.AnyOf {
			if evalFilter(sub, n, fc) {
				passed = true
				break
			}
		}
		if !passed {
			return false
		}
	}
	if f.Not != nil {
		if matchNode(*f.Not, n, fc) {
			return false
		}
	}
	return true
}

// literalArgumentMatches reports whether the call's positional argument at
// spec.Index is itself a literal whose text matches spec.Pattern. The
// argument node is checked directly, never its descendants: a dict or object
// payload containing literals is not a literal argument.
func literalArgumentMatches(n *ir.IRNode, spec rules.LiteralArgumentPattern) bool {
	args := argumentNodes(n)
	i := spec.Index
	if i < 0 {
		i += len(args)
	}
	if i < 0 || i >= len(args) {
		return false
	}
	a := args[i]
	if a.Kind == ir.NodeKindIdentifier {
		a = boundLiteral(n, a.Text)
		if a == nil {
			return false
		}
	}
	if a.Kind != ir.NodeKindLiteral {
		return false
	}
	return cachedRegexp(spec.Pattern).MatchString(literalNodeText(a))
}

// boundLiteral resolves an identifier argument to the literal it is bound to:
// the right-hand side of the assignments to name in the call's enclosing
// function, falling back to the file's top level. It returns nil unless every
// assignment to name in that scope is a plain literal -- a variable that is
// sometimes computed is not a hardcoded value. This is what lets
// `const mnemonic = '...'; fromPhrase(mnemonic)` and
// `key = '...'; Fernet(key)` match like an inline literal.
func boundLiteral(call *ir.IRNode, name string) *ir.IRNode {
	for scope := enclosingScope(call); scope != nil; scope = enclosingScope(scope) {
		var lit *ir.IRNode
		consistent := true
		seen := false
		ir.Walk(scope, func(c *ir.IRNode) bool {
			// Nested functions are their own scope; the outer walk must not
			// pick up their locals.
			if c != scope && c.Kind == ir.NodeKindFunction {
				return false
			}
			if c.Kind != ir.NodeKindAssignment || len(c.Children) == 0 {
				return true
			}
			if lhs, _ := c.Attrs["lhs"].(string); strings.TrimSpace(lhs) != name {
				return true
			}
			seen = true
			rhs := c.Children[len(c.Children)-1]
			if rhs.Kind != ir.NodeKindLiteral {
				consistent = false
				return true
			}
			lit = rhs
			return true
		})
		if seen {
			if consistent {
				return lit
			}
			return nil
		}
		if scope.Parent == nil {
			break
		}
	}
	return nil
}

// enclosingScope returns the nearest function ancestor of n, or the root.
// Called on a root it returns nil.
func enclosingScope(n *ir.IRNode) *ir.IRNode {
	if n.Parent == nil {
		return nil
	}
	p := n.Parent
	for p.Parent != nil && p.Kind != ir.NodeKindFunction {
		p = p.Parent
	}
	return p
}

// literalNodeText returns a literal's value text. Builders set Text on string
// literals to the unquoted value; a literal whose Text is empty (a prefixed
// Python bytes literal b'...' keeps its own children) falls back to the
// concatenated text of its leaves.
func literalNodeText(n *ir.IRNode) string {
	if n.Text != "" {
		return n.Text
	}
	var b strings.Builder
	for _, d := range ir.Descendants(n) {
		if len(d.Children) == 0 {
			b.WriteString(d.Text)
		}
	}
	return b.String()
}

// lhsFlowsToCall reports whether an assignment's target identifier is passed
// as an argument to a call whose callee chain matches re, anywhere in the
// enclosing function (or the whole file for a top-level assignment). The
// callee chain is the call's own callee text plus the callee text of every
// call nested in its receiver, so createHash('sha256').update(secret) reaches
// createHash.
func lhsFlowsToCall(n *ir.IRNode, re *regexp.Regexp) bool {
	if n.Kind != ir.NodeKindAssignment {
		return false
	}
	name, _ := n.Attrs["lhs"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	scope := n
	for scope.Parent != nil && scope.Kind != ir.NodeKindFunction {
		scope = scope.Parent
	}
	found := false
	ir.Walk(scope, func(c *ir.IRNode) bool {
		if found {
			return false
		}
		if c.Kind != ir.NodeKindCall || !argumentsReference(c, name) {
			return true
		}
		for _, t := range calleeChain(c) {
			if re.MatchString(t) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// argumentsReference reports whether name appears as an identifier in any of
// the call's arguments (or their subtrees).
func argumentsReference(c *ir.IRNode, name string) bool {
	for _, a := range argumentNodes(c) {
		if a.Kind == ir.NodeKindIdentifier && a.Text == name {
			return true
		}
		for _, d := range ir.Descendants(a) {
			if d.Kind == ir.NodeKindIdentifier && d.Text == name {
				return true
			}
		}
	}
	return false
}

// calleeChain returns the callee text of c and of every call nested in c's
// callee expression (the receiver side of a method chain).
func calleeChain(c *ir.IRNode) []string {
	out := []string{calleeText(c)}
	if len(c.Children) == 0 {
		return out
	}
	for _, d := range ir.Descendants(c.Children[0]) {
		if d.Kind == ir.NodeKindCall {
			out = append(out, calleeText(d))
		}
	}
	return out
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
		return taint.IsSource(lang, calleeTextFor(n, lang)+"(")
	case ir.NodeKindAttribute:
		return taint.IsSource(lang, attributeTextFor(n, lang))
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
	return taintedIdentifierInFilters(pattern.Filters, n, taintedVars, lang)
}

// taintedIdentifierInFilters is taintedIdentifierFor over a filter list,
// recursing into any_of entries (which keep positive polarity) but never
// into a not sub-pattern.
func taintedIdentifierInFilters(filters []rules.Filter, n *ir.IRNode, taintedVars map[string]bool, lang core.Language) string {
	for _, f := range filters {
		if len(f.AnyOf) > 0 {
			if id := taintedIdentifierInFilters(f.AnyOf, n, taintedVars, lang); id != "" {
				return id
			}
		}
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
			return sourceExpressionText(argRoot, lang)
		}
		for _, d := range ir.Descendants(argRoot) {
			if isDirectSourceExpression(d, lang) {
				return sourceExpressionText(d, lang)
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
func sourceExpressionText(n *ir.IRNode, lang core.Language) string {
	switch n.Kind {
	case ir.NodeKindCall:
		return calleeTextFor(n, lang)
	case ir.NodeKindAttribute:
		return attributeTextFor(n, lang)
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
		return sourceExpressionText(rhs, lang)
	}
	for _, d := range ir.Descendants(rhs) {
		if isDirectSourceExpression(d, lang) {
			return sourceExpressionText(d, lang)
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
