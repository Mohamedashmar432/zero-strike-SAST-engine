//go:build cgo

package csharp

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// IRBuilder converts a C# tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// Build parses source and walks the resulting CST to produce an IRFile.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("csharp builder: %w", err)
	}
	var warnings []ir.BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	return &ir.IRFile{
		Language: core.LangCSharp,
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
	case "compilation_unit":
		return ir.NodeKindModule
	case "method_declaration", "local_function_statement", "constructor_declaration", "lambda_expression":
		return ir.NodeKindFunction
	case "class_declaration", "struct_declaration", "record_declaration":
		return ir.NodeKindClass
	case "invocation_expression", "object_creation_expression", "implicit_object_creation_expression":
		return ir.NodeKindCall
	case "assignment_expression", "variable_declarator":
		return ir.NodeKindAssignment
	case "using_directive":
		return ir.NodeKindImport
	case "string_literal", "verbatim_string_literal", "raw_string_literal",
		"interpolated_string_expression", "character_literal",
		"integer_literal", "real_literal", "boolean_literal", "null_literal":
		return ir.NodeKindLiteral
	case "identifier":
		return ir.NodeKindIdentifier
	case "block":
		return ir.NodeKindBlock
	case "return_statement":
		return ir.NodeKindReturn
	case "if_statement":
		return ir.NodeKindIf
	case "for_statement", "foreach_statement":
		return ir.NodeKindFor
	case "while_statement", "do_statement":
		return ir.NodeKindWhile
	case "try_statement":
		return ir.NodeKindTry
	case "member_access_expression", "element_access_expression":
		return ir.NodeKindAttribute
	case "binary_expression":
		return ir.NodeKindBinaryOp
	default:
		return ir.NodeKindUnknown
	}
}

func extractAttrs(n *ir.IRNode, node *sitter.Node, source []byte) {
	switch node.Type() {
	case "invocation_expression", "object_creation_expression", "implicit_object_creation_expression":
		args := node.ChildByFieldName("arguments")
		if args == nil {
			args = childOfType(node, "argument_list")
		}
		if args != nil {
			argCount := 0
			for j := 0; j < int(args.ChildCount()); j++ {
				t := args.Child(j).Type()
				if t != "," && t != "(" && t != ")" {
					argCount++
				}
			}
			n.Attrs["argument_count"] = argCount
		}
	case "assignment_expression":
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
		if rhs := node.ChildByFieldName("right"); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
		}
		// Compound assignment (x += y) keeps x's previous value flowing
		// into the result; the taint pass treats it as taint-preserving.
		if op := node.ChildByFieldName("operator"); op != nil && op.Content(source) != "=" {
			n.Attrs["augmented"] = true
		}
	case "variable_declarator":
		// var x = ... — a declaration with an initializer, distinct from
		// assignment_expression (plain reassignment) in this grammar.
		name := node.ChildByFieldName("name")
		if name == nil {
			name = childOfType(node, "identifier")
		}
		if name != nil {
			n.Attrs["lhs"] = name.Content(source)
		}
		if rhs := declaratorInitializer(node); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
		}
	case "method_declaration", "local_function_statement", "constructor_declaration":
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["function_name"] = name.Content(source)
		}
		if params := extractParameters(node, source); len(params) > 0 {
			n.Attrs["parameters"] = params
		}
	case "lambda_expression":
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
	case "try_statement":
		var handlers []ir.ExceptHandler
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "catch_clause" {
				body := child.ChildByFieldName("body")
				if body == nil {
					body = childOfType(child, "block")
				}
				handlers = append(handlers, ir.ExceptHandler{IsEmptyBody: isEmptyBlockBody(body)})
			}
		}
		if len(handlers) > 0 {
			n.Attrs["except_handlers"] = handlers
		}
	}
}

// declaratorInitializer returns the initializer expression of a
// variable_declarator, handling both grammar shapes: a named "initializer"
// field, or an anonymous "=" token followed by the expression.
func declaratorInitializer(node *sitter.Node) *sitter.Node {
	if init := node.ChildByFieldName("initializer"); init != nil {
		// Older grammar versions wrap the expression in equals_value_clause;
		// newer ones point the field straight at the expression.
		if init.Type() == "equals_value_clause" {
			for i := int(init.ChildCount()) - 1; i >= 0; i-- {
				if c := init.Child(i); c.Type() != "=" {
					return c
				}
			}
			return nil
		}
		return init
	}
	// Fallback: expression following the "=" token.
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == "=" && i+1 < int(node.ChildCount()) {
			return node.Child(i + 1)
		}
	}
	return nil
}

// extractParameters collects the declared parameter names of a
// function-like node into a string slice.
func extractParameters(node *sitter.Node, source []byte) []string {
	params := node.ChildByFieldName("parameters")
	if params == nil {
		params = childOfType(node, "parameter_list")
	}
	if params == nil {
		return nil
	}
	var out []string
	for i := 0; i < int(params.ChildCount()); i++ {
		p := params.Child(i)
		switch p.Type() {
		case "parameter", "implicit_parameter":
			if name := p.ChildByFieldName("name"); name != nil {
				out = append(out, name.Content(source))
				continue
			}
			// Fallback: the parameter name is the last identifier child
			// (an earlier identifier may be a type name).
			for j := int(p.ChildCount()) - 1; j >= 0; j-- {
				if c := p.Child(j); c.Type() == "identifier" {
					out = append(out, c.Content(source))
					break
				}
			}
		case "identifier":
			// Single-parameter lambda: x => ...
			out = append(out, p.Content(source))
		}
	}
	return out
}

// childOfType returns the first direct child with the given node type.
func childOfType(node *sitter.Node, nodeType string) *sitter.Node {
	for i := 0; i < int(node.ChildCount()); i++ {
		if c := node.Child(i); c.Type() == nodeType {
			return c
		}
	}
	return nil
}

// isEmptyBlockBody reports whether a block (catch body) contains no real
// statements — only braces and/or comments.
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
