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
		kind := ir.NodeKind(r.Match.Kind)
		switch {
		case kind == ir.NodeKindCall && r.Match.Callee != "" && r.Match.CalleeSuffix && strings.Contains(r.Match.Callee, "."):
			// ponytail: "contains a dot" is the ≥2-segment floor — the
			// Validator already rejects callee_suffix:true on a
			// single-segment callee, so this precondition is guaranteed,
			// not just assumed, by the time a rule reaches here.
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
	var out []MatchResult
	fileLang := mc.File.IR.Language
	ir.Walk(mc.File.IR.Root, func(n *ir.IRNode) bool {
		candidates := mc.Index.byKind[n.Kind]
		if n.Kind == ir.NodeKindCall {
			text := calleeText(n)
			candidates = append(candidates, mc.Index.byCallee[text]...)
			for _, r := range mc.Index.byCalleeSuffix[lastCalleeSegment(text)] {
				if calleeSuffixMatches(r.Match.Callee, text) {
					candidates = append(candidates, r)
				}
			}
		}
		for _, r := range candidates {
			// A rule only applies to files of its own declared language — the
			// IR shape (assignment/call/try nodes) is language-agnostic, so
			// e.g. a Python "hardcoded credential" rule would otherwise also
			// match an identical-looking assignment in a Go or C# file.
			if r.Language != fileLang {
				continue
			}
			if matchNode(r.Match, n, taintedVars, fileLang) {
				out = append(out, MatchResult{Rule: r, Node: n, TaintedVar: taintedIdentifierFor(r.Match, n, taintedVars, fileLang)})
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
func matchNode(pattern rules.MatchPattern, n *ir.IRNode, taintedVars map[string]bool, lang core.Language) bool {
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
		if !evalFilter(f, n, taintedVars, lang) {
			return false
		}
	}
	return true
}

func evalFilter(f rules.Filter, n *ir.IRNode, taintedVars map[string]bool, lang core.Language) bool {
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
		if !anyArgument(n, func(a *ir.IRNode) bool {
			return a.Kind == ir.NodeKindIdentifier && taintedVars[a.Text]
		}) && !anyArgument(n, func(a *ir.IRNode) bool {
			return isDirectSourceExpression(a, lang)
		}) {
			return false
		}
	}
	if f.Kwarg != nil {
		if !anyArgument(n, func(a *ir.IRNode) bool {
			if a.Kind != ir.NodeKindKeywordArg {
				return false
			}
			name, _ := a.Attrs["kwarg_name"].(string)
			if name != f.Kwarg.Name {
				return false
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
	if f.TaintedRHS {
		if !rhsIsTainted(n, taintedVars, lang) {
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
		if matchNode(*f.Not, n, taintedVars, lang) {
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
func rhsIsTainted(n *ir.IRNode, taintedVars map[string]bool, lang core.Language) bool {
	if n.Kind != ir.NodeKindAssignment || len(n.Children) == 0 {
		return false
	}
	rhs := n.Children[len(n.Children)-1]
	if rhs.Kind == ir.NodeKindIdentifier && taintedVars[rhs.Text] {
		return true
	}
	if isDirectSourceExpression(rhs, lang) {
		return true
	}
	for _, d := range ir.Descendants(rhs) {
		if d.Kind == ir.NodeKindIdentifier && taintedVars[d.Text] {
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
