//go:build cgo

package typescript

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

// IRBuilder converts a TypeScript tree-sitter CST into an ir.IRFile.
// TypeScript is a superset of JavaScript — the same node types appear, plus
// TS-specific nodes (interface_declaration, type_alias_declaration, decorator,
// type_annotation, etc.) which map to NodeKindUnknown until taint analysis lands.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// Build parses source and walks the resulting CST to produce an IRFile.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("ts builder: %w", err)
	}
	var warnings []ir.BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	return &ir.IRFile{
		Language: core.LangTypeScript,
		Path:     path,
		Root:     root,
	}, warnings, nil
}

func (b *IRBuilder) buildNode(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning) *ir.IRNode {
	if node == nil {
		return nil
	}
	if node.IsError() || node.Type() == "ERROR" {
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
	if node.ChildCount() == 0 {
		irNode.Text = node.Content(source)
	}
	extractAttrs(irNode, node, source)
	irNode.Children = b.buildChildren(node, source, irNode, path, warnings)
	return irNode
}

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

func mapKind(nodeType string) ir.NodeKind {
	switch nodeType {
	// ── Shared with JavaScript ─────────────────────────────────────────────
	case "program":
		return ir.NodeKindModule
	case "function_declaration", "function_expression", "arrow_function",
		"method_definition", "function_signature":
		return ir.NodeKindFunction
	case "class_declaration", "class_expression":
		return ir.NodeKindClass
	case "call_expression", "new_expression":
		return ir.NodeKindCall
	case "assignment_expression", "augmented_assignment_expression", "variable_declarator":
		return ir.NodeKindAssignment
	case "import_statement", "import_declaration":
		return ir.NodeKindImport
	case "string", "template_string", "number", "true", "false", "null", "undefined":
		return ir.NodeKindLiteral
	case "identifier", "property_identifier", "shorthand_property_identifier":
		return ir.NodeKindIdentifier
	case "statement_block":
		return ir.NodeKindBlock
	case "return_statement":
		return ir.NodeKindReturn
	case "if_statement":
		return ir.NodeKindIf
	case "for_statement", "for_in_statement":
		return ir.NodeKindFor
	case "while_statement":
		return ir.NodeKindWhile
	case "try_statement":
		return ir.NodeKindTry
	case "member_expression", "subscript_expression":
		return ir.NodeKindAttribute
	case "binary_expression", "logical_expression":
		return ir.NodeKindBinaryOp
	case "pair":
		return ir.NodeKindKeywordArg
	// ── TypeScript-specific (no IR kind yet — pass through as Unknown) ─────
	case "interface_declaration", "type_alias_declaration",
		"type_annotation", "type_parameters", "type_arguments",
		"as_expression", "non_null_expression",
		"decorator", "accessibility_modifier",
		"enum_declaration", "namespace_declaration",
		"ambient_declaration":
		return ir.NodeKindUnknown
	default:
		return ir.NodeKindUnknown
	}
}

func extractAttrs(n *ir.IRNode, node *sitter.Node, source []byte) {
	switch node.Type() {
	case "call_expression", "new_expression":
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "arguments" {
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
	case "function_declaration", "function_expression", "arrow_function", "method_definition":
		if params := extractParameters(node, source); len(params) > 0 {
			n.Attrs["parameters"] = params
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
	case "assignment_expression", "augmented_assignment_expression":
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
		if rhs := node.ChildByFieldName("right"); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
		}
		if node.Type() == "augmented_assignment_expression" {
			// x += y keeps x's previous value flowing into the result;
			// the taint pass treats it as taint-preserving.
			n.Attrs["augmented"] = true
		}
	case "variable_declarator":
		// const/let/var x = ... — a declaration with an initializer, distinct
		// from assignment_expression (plain reassignment) in this grammar.
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["lhs"] = name.Content(source)
		}
		if value := node.ChildByFieldName("value"); value != nil {
			n.Attrs["rhs"] = value.Content(source)
		}
	case "pair":
		if key := node.ChildByFieldName("key"); key != nil {
			n.Attrs["kwarg_name"] = key.Content(source)
		}
		if value := node.ChildByFieldName("value"); value != nil {
			n.Attrs["kwarg_value"] = value.Content(source)
		}
	case "try_statement":
		var handlers []ir.ExceptHandler
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "catch_clause" {
				body := child.ChildByFieldName("body")
				handlers = append(handlers, ir.ExceptHandler{IsEmptyBody: isEmptyBlockBody(body)})
			}
		}
		if len(handlers) > 0 {
			n.Attrs["except_handlers"] = handlers
		}
	}
}

// extractParameters collects the declared parameter names of a function-like
// node into a string slice. The TypeScript grammar wraps each parameter in a
// required_parameter/optional_parameter node with a "pattern" field; plain
// identifiers and JS-style defaulted/rest parameters are handled as well.
// Destructuring patterns are skipped.
func extractParameters(node *sitter.Node, source []byte) []string {
	params := node.ChildByFieldName("parameters")
	if params == nil {
		// Single-parameter arrow function: x => ...
		if p := node.ChildByFieldName("parameter"); p != nil && p.Type() == "identifier" {
			return []string{p.Content(source)}
		}
		return nil
	}
	var out []string
	for i := 0; i < int(params.ChildCount()); i++ {
		p := params.Child(i)
		switch p.Type() {
		case "identifier":
			out = append(out, p.Content(source))
		case "required_parameter", "optional_parameter":
			if pat := p.ChildByFieldName("pattern"); pat != nil && pat.Type() == "identifier" {
				out = append(out, pat.Content(source))
				continue
			}
			for j := 0; j < int(p.ChildCount()); j++ {
				if c := p.Child(j); c.Type() == "identifier" {
					out = append(out, c.Content(source))
					break
				}
			}
		case "assignment_pattern":
			if left := p.ChildByFieldName("left"); left != nil && left.Type() == "identifier" {
				out = append(out, left.Content(source))
			}
		case "rest_pattern":
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

// isEmptyBlockBody reports whether a statement_block (catch body) contains no
// real statements — only braces and/or comments.
func isEmptyBlockBody(body *sitter.Node) bool {
	if body == nil {
		return false
	}
	for i := 0; i < int(body.ChildCount()); i++ {
		switch body.Child(i).Type() {
		case "{", "}", "comment":
			continue
		default:
			return false
		}
	}
	return true
}
