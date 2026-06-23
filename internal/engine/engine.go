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
	Index   *RuleIndex            // prebuilt at rule-load time, shared across files
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
	var out []MatchResult
	ir.Walk(mc.File.IR.Root, func(n *ir.IRNode) bool {
		candidates := mc.Index.byKind[n.Kind]
		if n.Kind == ir.NodeKindCall {
			candidates = append(candidates, mc.Index.byCallee[calleeText(n)]...)
		}
		for _, r := range candidates {
			if matchNode(r.Match, n) {
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
func matchNode(pattern rules.MatchPattern, n *ir.IRNode) bool {
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
	for _, f := range pattern.Filters {
		if !evalFilter(f, n) {
			return false
		}
	}
	return true
}

func evalFilter(f rules.Filter, n *ir.IRNode) bool {
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
	if f.Not != nil {
		if matchNode(*f.Not, n) {
			return false
		}
	}
	return true
}
