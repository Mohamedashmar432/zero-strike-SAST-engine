//go:build cgo

package php

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

// IRBuilder converts a PHP tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// Build parses source and walks the resulting CST to produce an IRFile.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("php builder: %w", err)
	}
	var warnings []ir.BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	return &ir.IRFile{
		Language: core.LangPHP,
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
	// echo is a language construct, not a call, but every rule-matching
	// primitive in internal/engine (TaintedArgument/calleeText) is built
	// around NodeKindCall. Rather than teach the engine a new statement-kind
	// match path, echo_statement is built with the exact shape a real
	// echo(...) call would have: a synthetic "echo" identifier followed by
	// the echoed expression(s) as arguments.
	// ponytail: synthetic-call shape for echo; revisit only if PHP needs a
	// true statement-kind (non-call) match in the rule engine.
	if node.Type() == "echo_statement" {
		return b.buildEchoAsCall(node, source, parent, path, warnings)
	}
	// include/require are language constructs (include_expression /
	// require_expression), not function_call_expression, so they'd
	// otherwise fall through to NodeKindUnknown — same problem
	// echo_statement already had, same fix: build a synthetic
	// NodeKindCall with a synthetic "include"/"require" identifier so
	// TaintedArgument (LFI rules) can find them like any other sink call.
	if node.Type() == "include_expression" || node.Type() == "require_expression" {
		keyword := "include"
		if node.Type() == "require_expression" {
			keyword = "require"
		}
		return b.buildIncludeAsCall(node, source, parent, path, warnings, keyword)
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
	// variable_name and dynamic_variable_name have internal children ($ token
	// + name subtree). Set Text to the full source span so that taint tracking
	// and argument matching can identify them by their variable name (e.g.
	// "$cmd", "$_GET") rather than finding an empty Text.
	if irNode.Kind == ir.NodeKindIdentifier && irNode.Text == "" {
		irNode.Text = node.Content(source)
	}
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

// buildEchoAsCall builds an echo_statement as a NodeKindCall whose first
// child is a synthetic "echo" identifier and whose remaining children are
// the echoed expression(s) — see the buildNode comment for why.
func (b *IRBuilder) buildEchoAsCall(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning) *ir.IRNode {
	start := node.StartPoint()
	end := node.EndPoint()
	loc := core.Location{
		StartLine: int(start.Row) + 1,
		StartCol:  int(start.Column),
		EndLine:   int(end.Row) + 1,
		EndCol:    int(end.Column),
	}
	irNode := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindCall,
		Location: loc,
		Parent:   parent,
		Attrs:    make(map[string]any),
	}
	echoIdent := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindIdentifier,
		Text:     "echo",
		Location: loc,
		Parent:   irNode,
		Attrs:    make(map[string]any),
	}
	children := []*ir.IRNode{echoIdent}
	argCount := 0
	for i := 0; i < int(node.ChildCount()); i++ {
		c := node.Child(i)
		switch c.Type() {
		case "echo", ";", ",":
			continue
		}
		built := b.buildNode(c, source, irNode, path, warnings)
		if built != nil {
			children = append(children, built)
			argCount++
		}
	}
	irNode.Attrs["argument_count"] = argCount
	irNode.Children = children
	return irNode
}

// buildIncludeAsCall builds an include_expression/require_expression as a
// NodeKindCall whose first child is a synthetic identifier holding keyword
// ("include" or "require") and whose remaining child is the included path
// expression — see the buildNode comment for why. The path expression may
// itself be a generic parenthesized-expression wrapper (include($f)) or a
// bare expression (include $f), same ambiguity buildEchoAsCall's comma-args
// don't have; anyArgument/firstTaintedArgument already recurse into a
// child's descendants, so no unwrapping is needed here.
func (b *IRBuilder) buildIncludeAsCall(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning, keyword string) *ir.IRNode {
	start := node.StartPoint()
	end := node.EndPoint()
	loc := core.Location{
		StartLine: int(start.Row) + 1,
		StartCol:  int(start.Column),
		EndLine:   int(end.Row) + 1,
		EndCol:    int(end.Column),
	}
	irNode := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindCall,
		Location: loc,
		Parent:   parent,
		Attrs:    make(map[string]any),
	}
	kwIdent := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindIdentifier,
		Text:     keyword,
		Location: loc,
		Parent:   irNode,
		Attrs:    make(map[string]any),
	}
	children := []*ir.IRNode{kwIdent}
	argCount := 0
	for i := 0; i < int(node.ChildCount()); i++ {
		c := node.Child(i)
		if c.Type() == keyword {
			continue
		}
		built := b.buildNode(c, source, irNode, path, warnings)
		if built != nil {
			children = append(children, built)
			argCount++
		}
	}
	irNode.Attrs["argument_count"] = argCount
	irNode.Children = children
	return irNode
}

func mapKind(nodeType string) ir.NodeKind {
	switch nodeType {
	case "program":
		return ir.NodeKindModule
	case "function_definition", "method_declaration":
		return ir.NodeKindFunction
	case "class_declaration":
		return ir.NodeKindClass
	case "function_call_expression", "member_call_expression", "scoped_call_expression":
		return ir.NodeKindCall
	case "assignment_expression", "augmented_assignment_expression":
		return ir.NodeKindAssignment
	case "namespace_use_declaration":
		return ir.NodeKindImport
	case "string", "encapsed_string", "nowdoc_string", "integer", "float", "boolean", "null":
		return ir.NodeKindLiteral
	case "variable_name", "dynamic_variable_name", "name":
		return ir.NodeKindIdentifier
	case "compound_statement":
		return ir.NodeKindBlock
	case "return_statement":
		return ir.NodeKindReturn
	case "if_statement":
		return ir.NodeKindIf
	case "for_statement", "foreach_statement":
		return ir.NodeKindFor
	case "while_statement":
		return ir.NodeKindWhile
	case "switch_statement":
		return ir.NodeKindSwitch
	case "try_statement":
		return ir.NodeKindTry
	case "binary_expression":
		return ir.NodeKindBinaryOp
	default:
		// ponytail: constructs no Sprint-14 rule needs (traits, enums,
		// match_block, ...) fall through to Unknown rather than growing
		// the switch speculatively. Add a case when a rule needs one.
		return ir.NodeKindUnknown
	}
}

func extractAttrs(n *ir.IRNode, node *sitter.Node, source []byte) {
	switch node.Type() {
	case "function_call_expression", "member_call_expression", "scoped_call_expression":
		args := node.ChildByFieldName("arguments")
		if args == nil {
			args = childOfType(node, "arguments")
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
	case "assignment_expression", "augmented_assignment_expression":
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
		if rhs := node.ChildByFieldName("right"); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
		}
		if node.Type() == "augmented_assignment_expression" {
			// x .= y / x += y keep x's previous value flowing into the
			// result; the taint pass treats it as taint-preserving.
			n.Attrs["augmented"] = true
		}
	case "function_definition", "method_declaration":
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["function_name"] = name.Content(source)
		}
		if params := extractParameters(node, source); len(params) > 0 {
			n.Attrs["parameters"] = params
		}
	case "return_statement":
		if expr := node.ChildByFieldName("return_expression"); expr != nil {
			n.Attrs["return_expr"] = expr.Content(source)
			break
		}
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
					body = childOfType(child, "compound_statement")
				}
				handlers = append(handlers, ir.ExceptHandler{IsEmptyBody: isEmptyBlockBody(body)})
			}
		}
		if len(handlers) > 0 {
			n.Attrs["except_handlers"] = handlers
		}
	}
}

// extractParameters collects the declared parameter names of a
// function-like node into a string slice.
func extractParameters(node *sitter.Node, source []byte) []string {
	params := node.ChildByFieldName("parameters")
	if params == nil {
		params = childOfType(node, "formal_parameters")
	}
	if params == nil {
		return nil
	}
	var out []string
	for i := 0; i < int(params.ChildCount()); i++ {
		p := params.Child(i)
		switch p.Type() {
		case "simple_parameter", "variadic_parameter", "property_promotion_parameter":
			if name := p.ChildByFieldName("name"); name != nil {
				out = append(out, name.Content(source))
				continue
			}
			// Fallback: the parameter name is the variable_name child.
			if v := childOfType(p, "variable_name"); v != nil {
				out = append(out, v.Content(source))
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
