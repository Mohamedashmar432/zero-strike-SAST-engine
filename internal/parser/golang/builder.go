//go:build cgo

package golang

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// IRBuilder converts a Go tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// Build parses source and walks the resulting CST to produce an IRFile.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("golang builder: %w", err)
	}
	var warnings []ir.BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	return &ir.IRFile{
		Language: core.LangGo,
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
	case "source_file":
		return ir.NodeKindModule
	case "function_declaration", "method_declaration", "func_literal":
		return ir.NodeKindFunction
	case "call_expression":
		return ir.NodeKindCall
	case "assignment_statement", "short_var_declaration", "var_spec", "const_spec":
		return ir.NodeKindAssignment
	case "import_declaration":
		return ir.NodeKindImport
	case "identifier", "blank_identifier", "field_identifier", "package_identifier", "type_identifier":
		return ir.NodeKindIdentifier
	case "block":
		return ir.NodeKindBlock
	case "return_statement":
		return ir.NodeKindReturn
	case "if_statement":
		return ir.NodeKindIf
	case "for_statement":
		return ir.NodeKindFor
	case "expression_switch_statement", "type_switch_statement":
		return ir.NodeKindSwitch
	case "select_statement":
		return ir.NodeKindSelect
	case "defer_statement":
		return ir.NodeKindDefer
	case "selector_expression":
		return ir.NodeKindAttribute
	case "binary_expression":
		return ir.NodeKindBinaryOp
	case "interpreted_string_literal", "raw_string_literal", "int_literal",
		"float_literal", "imaginary_literal", "rune_literal":
		return ir.NodeKindLiteral
	default:
		// ponytail: no rule this sprint needs go_statement/struct_type/
		// interface_type/etc. — they fall through to Unknown rather than
		// growing the switch speculatively. Add a case when a rule needs it.
		return ir.NodeKindUnknown
	}
}

func extractAttrs(n *ir.IRNode, node *sitter.Node, source []byte) {
	switch node.Type() {
	case "call_expression":
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
	case "assignment_statement":
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
	case "short_var_declaration":
		// x := ... — never compound, always a fresh binding.
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
		if rhs := node.ChildByFieldName("right"); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
		}
	case "var_spec", "const_spec":
		// var x = ... / const x = ... — declaration with an initializer,
		// using this grammar's "name"/"value" fields (not left/right).
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["lhs"] = name.Content(source)
		}
		if value := node.ChildByFieldName("value"); value != nil {
			n.Attrs["rhs"] = value.Content(source)
		}
	case "function_declaration", "method_declaration":
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["function_name"] = name.Content(source)
		}
		if params := extractParameters(node, source); len(params) > 0 {
			n.Attrs["parameters"] = params
		}
	case "func_literal":
		if params := extractParameters(node, source); len(params) > 0 {
			n.Attrs["parameters"] = params
		}
	case "return_statement":
		// Capture the returned expression(s)' text for the taint
		// function-summary pass (see internal/analyzer/taint). Go allows
		// multi-value returns; the whole expression_list is captured as one
		// text blob, matching this pass's existing single-value heuristic.
		for i := 0; i < int(node.ChildCount()); i++ {
			c := node.Child(i)
			if t := c.Type(); t != "return" && t != ";" {
				n.Attrs["return_expr"] = c.Content(source)
				break
			}
		}
	}
}

// extractParameters collects the declared parameter names of a
// function-like node into a string slice. Go allows grouped parameters
// (func f(a, b string)) where one parameter_declaration owns multiple
// name identifiers ahead of a single shared type — collect every
// identifier child, not just the first.
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
		if p.Type() != "parameter_declaration" && p.Type() != "variadic_parameter_declaration" {
			continue
		}
		for j := 0; j < int(p.ChildCount()); j++ {
			c := p.Child(j)
			if c.Type() == "identifier" {
				out = append(out, c.Content(source))
			}
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
