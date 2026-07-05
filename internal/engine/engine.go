package engine

import (
	"context"
	"regexp"
	"strings"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/rules"
)

// MatchResult is a single rule match against an IR node.
type MatchResult struct {
	Rule     *rules.Rule
	Node     *ir.IRNode
	Captures map[string]string
}

// Project provides cross-file context for multi-file analysis (nil in Sprint 1–2).
type Project struct {
	Root string
}

// RuleIndex is a prebuilt dispatch table enabling O(nodes) matching instead of O(rules × nodes).
// Callee-specific call rules are stored only in byCallee; all other rules go in byKind.
type RuleIndex struct {
	byKind   map[ir.NodeKind][]*rules.Rule
	byCallee map[string][]*rules.Rule
}

// BuildIndex groups rules by kind and callee at load time.
// Call once after loading rules; pass the result in MatchContext.Index per file.
func BuildIndex(rs []*rules.Rule) *RuleIndex {
	idx := &RuleIndex{
		byKind:   make(map[ir.NodeKind][]*rules.Rule),
		byCallee: make(map[string][]*rules.Rule),
	}
	for _, r := range rs {
		kind := ir.NodeKind(r.Match.Kind)
		if kind == ir.NodeKindCall && r.Match.Callee != "" {
			// callee-specific rules go only in byCallee to avoid double-matching
			idx.byCallee[r.Match.Callee] = append(idx.byCallee[r.Match.Callee], r)
		} else {
			idx.byKind[kind] = append(idx.byKind[kind], r)
		}
	}
	return idx
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
			candidates = append(candidates, mc.Index.byCallee[calleeText(n)]...)
		}
		for _, r := range candidates {
			// A rule only applies to files of its own declared language — the
			// IR shape (assignment/call/try nodes) is language-agnostic, so
			// e.g. a Python "hardcoded credential" rule would otherwise also
			// match an identical-looking assignment in a Go or C# file.
			if r.Language != fileLang {
				continue
			}
			if matchNode(r.Match, n, taintedVars) {
				out = append(out, MatchResult{Rule: r, Node: n})
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

func attributeText(n *ir.IRNode) string {
	var parts []string
	for _, c := range n.Children {
		if c.Kind == ir.NodeKindIdentifier && c.Text != "" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, ".")
}

// matchNode checks whether a node satisfies the match pattern.
// Callee matching is already handled by the index; matchNode covers
// Identifier, Literal, and Filter constraints.
func matchNode(pattern rules.MatchPattern, n *ir.IRNode, taintedVars map[string]bool) bool {
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
		if !evalFilter(f, n, taintedVars) {
			return false
		}
	}
	return true
}

func evalFilter(f rules.Filter, n *ir.IRNode, taintedVars map[string]bool) bool {
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
	if f.TaintedRHS {
		if !rhsIsTainted(n, taintedVars) {
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
		if matchNode(*f.Not, n, taintedVars) {
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
// contains an identifier present in taintedVars.
func rhsIsTainted(n *ir.IRNode, taintedVars map[string]bool) bool {
	if n.Kind != ir.NodeKindAssignment || len(n.Children) == 0 {
		return false
	}
	rhs := n.Children[len(n.Children)-1]
	if rhs.Kind == ir.NodeKindIdentifier && taintedVars[rhs.Text] {
		return true
	}
	for _, d := range ir.Descendants(rhs) {
		if d.Kind == ir.NodeKindIdentifier && taintedVars[d.Text] {
			return true
		}
	}
	return false
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
