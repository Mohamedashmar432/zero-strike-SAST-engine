package engine

import (
	"regexp"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// ArgumentHostFixed and ExcludeBareParameter support. Both answer a question
// the taint pass cannot: tainted_argument says a parameter or source reaches
// the call, not whether the part that reached it decides anything.

// fixedURLPrefix matches the leading text of a URL whose destination is
// already decided: scheme://host followed by a path, query or fragment
// delimiter, or a same-origin path ("/x" but not "//host" or "/\host"). The
// delimiter is required so "https://api.example" + suffix, where a suffix of
// ".evil.test" would still move the host, does not count.
var fixedURLPrefix = regexp.MustCompile(`^(https?://[A-Za-z0-9.-]+(:[0-9]+)?[/?#]|/[^/\\])`)

// urlHostFixed reports whether expression n evaluates to a URL whose scheme and
// host cannot be influenced by whatever the rest of the expression holds.
func (fc *fileCtx) urlHostFixed(n *ir.IRNode, depth int) bool {
	n = unwrapArgument(n)
	if n == nil || depth > 6 {
		return false
	}
	switch n.Kind {
	case ir.NodeKindLiteral:
		text := literalURLText(n.Text)
		if fixedURLPrefix.MatchString(text) {
			return true
		}
		// A template or interpolated string that opens with a substitution
		// (`${BASE}/users/${id}`, $"{baseUrl}/users/{id}"): the first
		// expression is the whole of the authority.
		if strings.HasPrefix(text, "${") || strings.HasPrefix(text, "{") {
			if lead := firstExpression(n); lead != nil {
				return fc.hostOperandFixed(lead, depth+1)
			}
		}
	case ir.NodeKindBinaryOp:
		ops := concatOperands(n)
		if len(ops) < 2 {
			return false
		}
		// Join the run of leading literals: "https://api.test" + "/v1/" + id.
		var prefix strings.Builder
		i := 0
		for ; i < len(ops) && ops[i].Kind == ir.NodeKindLiteral; i++ {
			prefix.WriteString(literalURLText(ops[i].Text))
		}
		if i > 0 {
			return fixedURLPrefix.MatchString(prefix.String())
		}
		return fc.hostOperandFixed(ops[0], depth+1)
	case ir.NodeKindIdentifier:
		return fc.hostOperandFixed(n, depth+1)
	}
	return false
}

// hostOperandFixed reports whether n, the leading operand of a URL, is
// configuration rather than request data.
func (fc *fileCtx) hostOperandFixed(n *ir.IRNode, depth int) bool {
	if depth > 6 {
		return false
	}
	switch n.Kind {
	case ir.NodeKindIdentifier:
		if !fc.tainted[n.Text] {
			// Module constant, imported base URL, local built from config.
			return true
		}
		// Tainted by seeding or by propagation: fixed only when every
		// assignment in the file builds it from a fixed-host URL. A parameter
		// has no such assignment and stays unresolved.
		//
		// The def-use tables are file-wide, so a parameter of some other
		// function that shares the name must not block the lookup: only this
		// function's own parameters and assignments count.
		fc.index()
		fn := enclosingFunction(n)
		if fn != nil {
			params, _ := fn.Attrs["parameters"].([]string)
			for _, p := range params {
				if p == n.Text {
					return false
				}
			}
		}
		var defs []*ir.IRNode
		for _, d := range fc.assigns[n.Text] {
			if f := enclosingFunction(d); f == nil || f == fn {
				defs = append(defs, d)
			}
		}
		if len(defs) == 0 {
			return false
		}
		for _, d := range defs {
			if len(d.Children) == 0 || !fc.urlHostFixed(d.Children[len(d.Children)-1], depth+1) {
				return false
			}
		}
		return true
	case ir.NodeKindAttribute:
		if isDirectSourceExpression(n, fc.lang) {
			return false
		}
		text := exprText(n, fc.lang)
		if strings.HasPrefix(text, "process.env.") || strings.HasPrefix(text, "this.") {
			return true
		}
		return !fc.subtreeTainted(n, false)
	case ir.NodeKindCall:
		if isDirectSourceExpression(n, fc.lang) {
			return false
		}
		return !fc.subtreeTainted(n, false)
	}
	return false
}

// unwrapArgument looks through the unnamed wrapper some builders (C#) put
// around each argument, returning the expression inside.
func unwrapArgument(n *ir.IRNode) *ir.IRNode {
	for n != nil && n.Kind == ir.NodeKindUnknown && n.Text == "" {
		var only *ir.IRNode
		count := 0
		for _, c := range n.Children {
			if c.Kind == ir.NodeKindUnknown && len(c.Children) == 0 {
				continue // punctuation
			}
			only = c
			count++
		}
		if count != 1 {
			break
		}
		n = only
	}
	return n
}

// literalURLText returns a string literal's value without its C# $/@ prefixes
// or surrounding quotes (the JS builders already unquote).
func literalURLText(s string) string {
	s = strings.TrimLeft(s, "$@")
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}

// firstExpression returns the first identifier, attribute or call inside a
// template or interpolated string, in source order.
func firstExpression(lit *ir.IRNode) *ir.IRNode {
	for _, d := range ir.Descendants(lit) {
		switch d.Kind {
		case ir.NodeKindIdentifier, ir.NodeKindAttribute, ir.NodeKindCall:
			return d
		}
	}
	return nil
}

// concatOperands flattens the left spine of a "+" chain into its operands.
func concatOperands(n *ir.IRNode) []*ir.IRNode {
	var out []*ir.IRNode
	for _, c := range n.Children {
		if c.Kind == ir.NodeKindUnknown && len(c.Children) == 0 {
			continue // operator token
		}
		if c.Kind == ir.NodeKindBinaryOp {
			out = append(out, concatOperands(c)...)
			continue
		}
		out = append(out, c)
	}
	return out
}

// isBareParameterArg reports whether identifier a, an argument of sink, is a
// parameter of the enclosing function that the function never reassigns, with
// no source pattern behind its taint.
func (fc *fileCtx) isBareParameterArg(sink, a *ir.IRNode) bool {
	if !fc.weak[a.Text] {
		return false
	}
	direct := false
	for _, arg := range argumentNodes(sink) {
		if unwrapArgument(arg) == a {
			direct = true
			break
		}
	}
	if !direct {
		return false
	}
	fn := enclosingFunction(sink)
	if fn == nil {
		return false
	}
	params, _ := fn.Attrs["parameters"].([]string)
	isParam := false
	for _, p := range params {
		if p == a.Text {
			isParam = true
			break
		}
	}
	if !isParam {
		return false
	}
	reassigned := false
	ir.Walk(fn, func(x *ir.IRNode) bool {
		if x.Kind == ir.NodeKindAssignment {
			lhs, _ := x.Attrs["lhs"].(string)
			for _, part := range strings.Split(lhs, ",") {
				if strings.TrimSpace(part) == a.Text {
					reassigned = true
				}
			}
		}
		return !reassigned
	})
	return !reassigned
}
