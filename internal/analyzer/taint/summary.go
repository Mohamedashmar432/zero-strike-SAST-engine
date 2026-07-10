package taint

import (
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// functionSummary classifies what a same-file function does with taint,
// derived from its return statements:
//
//   - passesThroughParam: at least one return statement returns one of the
//     function's own parameters unchanged, so a tainted argument taints the
//     return value.
//   - alwaysTainted: at least one return statement returns an expression
//     matching the language's taint sources, so every call site's return
//     value is tainted regardless of arguments.
type functionSummary struct {
	alwaysTainted      bool
	passesThroughParam bool
}

// buildSummaries walks every function node in the file once and returns a
// map of function name → summary. Nested functions get their own entries;
// return statements inside a nested function do not count toward the
// enclosing function's summary. Two same-named functions in one file
// collapse to the later entry (file-scoped model).
func buildSummaries(file *ir.IRFile, pats languagePatterns) map[string]functionSummary {
	summaries := make(map[string]functionSummary)
	if file == nil || file.Root == nil {
		return summaries
	}
	ir.Walk(file.Root, func(n *ir.IRNode) bool {
		if n.Kind != ir.NodeKindFunction {
			return true
		}
		name := functionName(n)
		if name != "" {
			summaries[name] = summarize(n, pats)
		}
		return true // keep walking: nested functions get their own summaries
	})
	return summaries
}

// summarize inspects one function's own return statements (excluding those
// of nested functions) and classifies its taint behavior.
func summarize(fn *ir.IRNode, pats languagePatterns) functionSummary {
	params := make(map[string]bool)
	if list, ok := fn.Attrs["parameters"].([]string); ok {
		for _, p := range list {
			params[p] = true
		}
	}
	var sum functionSummary
	ir.Walk(fn, func(d *ir.IRNode) bool {
		if d != fn && d.Kind == ir.NodeKindFunction {
			return false // don't attribute a nested function's returns to fn
		}
		if d.Kind != ir.NodeKindReturn {
			return true
		}
		expr, _ := d.Attrs["return_expr"].(string)
		if expr == "" {
			return true
		}
		if params[expr] {
			sum.passesThroughParam = true
		}
		if matchesAny(pats.Sources, expr) {
			sum.alwaysTainted = true
		}
		return true
	})
	return sum
}

// functionName returns a function node's name: the builder-extracted
// Attrs["function_name"] when present, else the first identifier child
// (matching internal/symboltable's resolution of the same node).
func functionName(fn *ir.IRNode) string {
	if v, ok := fn.Attrs["function_name"].(string); ok && v != "" {
		return v
	}
	for _, c := range fn.Children {
		if c.Kind == ir.NodeKindIdentifier && c.Text != "" {
			return c.Text
		}
	}
	return ""
}
