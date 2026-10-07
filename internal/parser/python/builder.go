//go:build cgo

package python

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// IRBuilder converts a Python tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// Build parses source and walks the resulting CST to produce an IRFile.
// Warnings are returned for any tree-sitter ERROR nodes encountered; the rest of
// the file is still analyzed. Build never panics on malformed input.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("python builder: %w", err)
	}
	// buildNode walks *sitter.Node pointers into the tree's C memory. Without
	// this, result is unreachable once RootNode is loaded and the GC finalizer
	// (ts_tree_delete) can free the CST mid-walk — a use-after-free that
	// silently drops random findings. Also frees promptly, not at GC time.
	defer result.Tree.Close()
	var warnings []ir.BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	if root != nil {
		if aliases := importAliases(result.RootNode, source); len(aliases) > 0 {
			root.Attrs["import_aliases"] = aliases
		}
	}
	return &ir.IRFile{
		Language: core.LangPython,
		Path:     path,
		Root:     root,
	}, warnings, nil
}

// buildNode converts a single tree-sitter node into an IRNode, recursing into children.
func (b *IRBuilder) buildNode(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning) *ir.IRNode {
	if node == nil {
		return nil
	}
	if node.IsError() || node.Type() == "ERROR" {
		// Skip ERROR subtree; emit a warning so the caller knows something was skipped.
		start := node.StartPoint()
		*warnings = append(*warnings, ir.BuildWarning{
			File:    path,
			Message: fmt.Sprintf("syntax error at %s:%d — subtree skipped", path, int(start.Row)+1),
			Line:    int(start.Row) + 1,
		})
		return nil
	}
	start := node.StartPoint()
	end := node.EndPoint()
	irNode := &ir.IRNode{
		NodeID: uuid.New().String(),
		Kind:   mapKind(node.Type()),
		Location: core.Location{
			StartLine: int(start.Row) + 1,
			StartCol:  int(start.Column),
			EndLine:   int(end.Row) + 1,
			EndCol:    int(end.Column),
		},
		Parent: parent,
		Attrs:  make(map[string]any),
	}
	// Set text for leaf nodes
	if node.ChildCount() == 0 {
		irNode.Text = node.Content(source)
	} else if irNode.Kind == ir.NodeKindLiteral {
		// tree-sitter-python string nodes wrap their value in
		// string_start/string_content/string_end children, so the leaf check
		// above never fires and Text would stay empty — silently breaking any
		// filter that reads a literal argument's value (e.g.
		// argument_literal_matches on hashlib.new("md5")). Mirrors the same
		// fix in the go/java/js/ts/csharp builders. Triple-quoted and
		// f-strings only lose one quote layer — no current rule needs those.
		irNode.Text = unquoteLiteral(node.Content(source))
	}
	extractAttrs(irNode, node, source)
	irNode.Children = b.buildChildren(node, source, irNode, path, warnings)
	return irNode
}

// unquoteLiteral strips one layer of matching outer quote characters (" or ')
// from a literal's raw source text, so filters like argument_literal_matches
// match the literal's actual value (e.g. md5) rather than its quoted source
// form (e.g. "md5"). Anything not quote-delimited (a bare numeric/boolean/
// None token) passes through unchanged.
func unquoteLiteral(raw string) string {
	if len(raw) >= 2 {
		first, last := raw[0], raw[len(raw)-1]
		if first == last && (first == '"' || first == '\'') {
			return raw[1 : len(raw)-1]
		}
	}
	return raw
}

// buildChildren iterates over all children and collects non-nil IRNodes.
func (b *IRBuilder) buildChildren(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning) []*ir.IRNode {
	count := int(node.ChildCount())
	children := make([]*ir.IRNode, 0, count)
	for i := 0; i < count; i++ {
		child := b.buildNode(node.Child(i), source, parent, path, warnings)
		if child != nil {
			children = append(children, child)
		}
	}
	return children
}

// mapKind converts a tree-sitter node type string to an ir.NodeKind.
func mapKind(nodeType string) ir.NodeKind {
	switch nodeType {
	case "module":
		return ir.NodeKindModule
	case "function_definition":
		return ir.NodeKindFunction
	case "class_definition":
		return ir.NodeKindClass
	case "call":
		return ir.NodeKindCall
	case "assignment", "augmented_assignment":
		return ir.NodeKindAssignment
	case "import_statement", "import_from_statement":
		return ir.NodeKindImport
	case "string", "integer", "float", "true", "false", "none":
		return ir.NodeKindLiteral
	case "identifier":
		return ir.NodeKindIdentifier
	case "block":
		return ir.NodeKindBlock
	case "return_statement":
		return ir.NodeKindReturn
	case "if_statement":
		return ir.NodeKindIf
	case "for_statement":
		return ir.NodeKindFor
	case "while_statement":
		return ir.NodeKindWhile
	case "try_statement":
		return ir.NodeKindTry
	case "attribute":
		return ir.NodeKindAttribute
	case "binary_operator":
		return ir.NodeKindBinaryOp
	case "assert_statement":
		return ir.NodeKindAssert
	case "keyword_argument":
		return ir.NodeKindKeywordArg
	case "decorator":
		return ir.NodeKindDecorator
	default:
		return ir.NodeKindUnknown
	}
}

// extractAttrs populates the Attrs map with language-specific metadata.
func extractAttrs(n *ir.IRNode, node *sitter.Node, source []byte) {
	switch node.Type() {
	case "call":
		// Count arguments from the argument_list child
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "argument_list" {
				// Count non-punctuation children as arguments
				argCount := 0
				for j := 0; j < int(child.ChildCount()); j++ {
					t := child.Child(j).Type()
					if t != "," && t != "(" && t != ")" {
						argCount++
					}
				}
				n.Attrs["argument_count"] = argCount
				break
			}
		}
	case "function_definition":
		// Extract the function name from the "name" child
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "identifier" {
				n.Attrs["function_name"] = child.Content(source)
				break
			}
		}
		if params := extractParameters(node, source); len(params) > 0 {
			n.Attrs["parameters"] = params
		}
		if decs := decoratorStack(node.Parent(), source); len(decs) > 0 {
			n.Attrs["decorators"] = decs
		}
	case "class_definition":
		if decs := decoratorStack(node.Parent(), source); len(decs) > 0 {
			n.Attrs["decorators"] = decs
		}
	case "decorator":
		// Lowered so rules can see decorators at all: before this a
		// decorated_definition's decorators were anonymous Unknown nodes and
		// no rule could express "a view decorated @csrf_exempt". Every
		// decorator of a stack becomes its own node, and each one carries the
		// whole stack so a rule can also reason about its siblings (e.g.
		// csrf_exempt next to require_GET).
		name, args := decoratorNameArgs(node, source)
		n.Text = name
		if args != "" {
			n.Attrs["decorator_args"] = args
		}
		if stack := decoratorStack(node.Parent(), source); len(stack) > 0 {
			n.Attrs["decorator_stack"] = stack
		}
		if def := decoratedDefinition(node.Parent()); def != nil {
			if nm := def.ChildByFieldName("name"); nm != nil {
				n.Attrs["decorated_name"] = nm.Content(source)
			}
		}
	case "as_pattern":
		// `with open(p, "w") as f:` binds f without an assignment node.
		// Recording the bound name lets the engine resolve what a later
		// f.write(...) writes to (see the written_file_matches filter).
		for i := 0; i < int(node.ChildCount()); i++ {
			if c := node.Child(i); c.Type() == "as_pattern_target" {
				n.Attrs["as_name"] = strings.TrimSpace(c.Content(source))
			}
		}
	case "assignment", "augmented_assignment":
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
		if rhs := node.ChildByFieldName("right"); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
		}
		if node.Type() == "augmented_assignment" {
			// x += y keeps x's previous value flowing into the result;
			// the taint pass treats it as taint-preserving.
			n.Attrs["augmented"] = true
		}
	case "return_statement":
		// Capture the returned expression's text for the taint
		// function-summary pass (see internal/analyzer/taint).
		for i := 0; i < int(node.ChildCount()); i++ {
			c := node.Child(i)
			if t := c.Type(); t != "return" && t != ";" {
				n.Attrs["return_expr"] = c.Content(source)
				break
			}
		}
	case "keyword_argument":
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["kwarg_name"] = name.Content(source)
		}
		if value := node.ChildByFieldName("value"); value != nil {
			n.Attrs["kwarg_value"] = value.Content(source)
		}
	case "try_statement":
		var handlers []ir.ExceptHandler
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "except_clause" {
				handlers = append(handlers, buildExceptHandler(child, source))
			}
		}
		if len(handlers) > 0 {
			n.Attrs["except_handlers"] = handlers
		}
	}
}

// extractParameters collects the declared parameter names of a
// function_definition into a string slice (positional, defaulted, typed,
// *args and **kwargs names — destructuring/tuple params are skipped).
func extractParameters(node *sitter.Node, source []byte) []string {
	params := node.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var out []string
	for i := 0; i < int(params.ChildCount()); i++ {
		p := params.Child(i)
		switch p.Type() {
		case "identifier":
			out = append(out, p.Content(source))
		case "default_parameter", "typed_default_parameter":
			if name := p.ChildByFieldName("name"); name != nil {
				out = append(out, name.Content(source))
			}
		case "typed_parameter", "list_splat_pattern", "dictionary_splat_pattern":
			for j := 0; j < int(p.ChildCount()); j++ {
				if c := p.Child(j); c.Type() == "identifier" {
					out = append(out, c.Content(source))
					break
				}
			}
		}
	}
	return out
}

// buildExceptHandler extracts metadata from a single except_clause tree-sitter
// node: whether it's a bare "except:", the exception type expression text(s)
// if any, and whether the handler body is just "pass".
func buildExceptHandler(clause *sitter.Node, source []byte) ir.ExceptHandler {
	var h ir.ExceptHandler
	var body *sitter.Node
	sawAs := false
	for i := 0; i < int(clause.ChildCount()); i++ {
		c := clause.Child(i)
		switch c.Type() {
		case "except", ":", "*":
			// keywords/punctuation — nothing to extract
		case "as":
			sawAs = true
		case "block":
			body = c
		default:
			if !sawAs {
				h.Types = append(h.Types, c.Content(source))
			}
			// after "as", the remaining child is the alias identifier — not a type
		}
	}
	h.IsBare = len(h.Types) == 0
	h.IsEmptyBody = isEmptyPassBody(body)
	return h
}

// isEmptyPassBody reports whether a block's only statement is "pass".
func isEmptyPassBody(body *sitter.Node) bool {
	if body == nil {
		return false
	}
	var stmts []*sitter.Node
	for i := 0; i < int(body.ChildCount()); i++ {
		c := body.Child(i)
		if c.Type() == "comment" {
			continue
		}
		stmts = append(stmts, c)
	}
	return len(stmts) == 1 && stmts[0].Type() == "pass_statement"
}

// decoratorNameArgs returns a decorator's dotted name without call
// arguments ("app.route" for "@app.route('/x', methods=['POST'])") and the
// argument list text, or "" when the decorator is not called.
func decoratorNameArgs(dec *sitter.Node, source []byte) (string, string) {
	for i := 0; i < int(dec.ChildCount()); i++ {
		c := dec.Child(i)
		switch c.Type() {
		case "@", "comment":
			continue
		case "call":
			name := ""
			if fn := c.ChildByFieldName("function"); fn != nil {
				name = compactSpace(fn.Content(source))
			}
			args := ""
			if a := c.ChildByFieldName("arguments"); a != nil {
				args = a.Content(source)
			}
			return name, args
		default:
			return compactSpace(c.Content(source)), ""
		}
	}
	return "", ""
}

// decoratedDefinition returns the function/class definition a
// decorated_definition wraps, or nil when n is not a decorated_definition.
func decoratedDefinition(n *sitter.Node) *sitter.Node {
	if n == nil || n.Type() != "decorated_definition" {
		return nil
	}
	if def := n.ChildByFieldName("definition"); def != nil {
		return def
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); c.Type() == "function_definition" || c.Type() == "class_definition" {
			return c
		}
	}
	return nil
}

// decoratorStack lists the names of every decorator on a
// decorated_definition, outermost first. It returns nil for any other node,
// so an undecorated definition gets no "decorators" attribute.
func decoratorStack(n *sitter.Node, source []byte) []string {
	if n == nil || n.Type() != "decorated_definition" {
		return nil
	}
	var out []string
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); c.Type() == "decorator" {
			if name, _ := decoratorNameArgs(c, source); name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

// compactSpace removes all whitespace from a dotted-name expression, which
// tree-sitter allows to span lines inside parentheses.
func compactSpace(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// importAliases builds the file's import table: local name -> canonical
// dotted path, for every binding that differs from the name it introduces.
//
//	from hashlib import md5             md5 -> hashlib.md5
//	from PIL import ImageMath as IM     IM  -> PIL.ImageMath
//	import xml.etree.ElementTree as ET  ET  -> xml.etree.ElementTree
//
// A plain `import os` binds os to os and needs no entry. Relative imports
// (`from . import views`) and wildcard imports are skipped: neither names a
// canonical module. A local name bound to two different targets anywhere in
// the file, or also defined locally as a function or class, is dropped as
// ambiguous rather than guessed.
func importAliases(root *sitter.Node, source []byte) map[string]string {
	out := make(map[string]string)
	ambiguous := make(map[string]bool)
	defined := make(map[string]bool)
	bind := func(local, canonical string) {
		if local == "" || canonical == "" || local == canonical {
			return
		}
		if prev, ok := out[local]; ok && prev != canonical {
			ambiguous[local] = true
		}
		out[local] = canonical
	}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case "function_definition", "class_definition":
			if nm := n.ChildByFieldName("name"); nm != nil {
				defined[nm.Content(source)] = true
			}
		case "import_statement":
			for i := 0; i < int(n.NamedChildCount()); i++ {
				c := n.NamedChild(i)
				if c.Type() != "aliased_import" {
					continue
				}
				name, alias := c.ChildByFieldName("name"), c.ChildByFieldName("alias")
				if name != nil && alias != nil {
					bind(alias.Content(source), compactSpace(name.Content(source)))
				}
			}
			return
		case "import_from_statement":
			mod := n.ChildByFieldName("module_name")
			if mod == nil || mod.Type() != "dotted_name" {
				return // relative import or malformed
			}
			module := compactSpace(mod.Content(source))
			for i := 0; i < int(n.NamedChildCount()); i++ {
				c := n.NamedChild(i)
				if c.StartByte() == mod.StartByte() && c.EndByte() == mod.EndByte() {
					continue
				}
				switch c.Type() {
				case "dotted_name":
					nm := compactSpace(c.Content(source))
					bind(nm, module+"."+nm)
				case "aliased_import":
					name, alias := c.ChildByFieldName("name"), c.ChildByFieldName("alias")
					if name != nil && alias != nil {
						bind(alias.Content(source), module+"."+compactSpace(name.Content(source)))
					}
				}
			}
			return
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(root)
	for k := range out {
		if ambiguous[k] || defined[k] {
			delete(out, k)
		}
	}
	return out
}
