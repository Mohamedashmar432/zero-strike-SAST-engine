//go:build cgo

package python

import (
	"context"
	"fmt"

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
	var warnings []ir.BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
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
	}
	extractAttrs(irNode, node, source)
	irNode.Children = b.buildChildren(node, source, irNode, path, warnings)
	return irNode
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
