//go:build cgo

package javascript

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

// IRBuilder converts a JavaScript tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// BuildWarning is a lightweight diagnostic emitted when the builder encounters a
// tree-sitter ERROR node.
type BuildWarning struct {
	File    string
	Message string
	Line    int
}

// Build parses source and walks the resulting CST to produce an IRFile.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("js builder: %w", err)
	}
	var warnings []BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	return &ir.IRFile{
		Language: core.LangJavaScript,
		Path:     path,
		Root:     root,
	}, warnings, nil
}

func (b *IRBuilder) buildNode(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]BuildWarning) *ir.IRNode {
	if node == nil {
		return nil
	}
	if node.IsError() || node.Type() == "ERROR" {
		start := node.StartPoint()
		*warnings = append(*warnings, BuildWarning{
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

func (b *IRBuilder) buildChildren(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]BuildWarning) []*ir.IRNode {
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
	case "program":
		return ir.NodeKindModule
	case "function_declaration", "function_expression", "arrow_function", "method_definition":
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
	case "assignment_expression", "augmented_assignment_expression":
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
		if rhs := node.ChildByFieldName("right"); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
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
