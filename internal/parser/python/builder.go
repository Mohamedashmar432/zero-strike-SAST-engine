//go:build cgo

package python

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

// IRBuilder converts a Python tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// BuildWarning is a lightweight diagnostic emitted when the builder encounters a
// tree-sitter ERROR node. It does not stop analysis of the surrounding file.
type BuildWarning struct {
	File    string
	Message string
	Line    int
}

// Build parses source and walks the resulting CST to produce an IRFile.
// Warnings are returned for any tree-sitter ERROR nodes encountered; the rest of
// the file is still analyzed. Build never panics on malformed input.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("python builder: %w", err)
	}
	var warnings []BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	return &ir.IRFile{
		Language: core.LangPython,
		Path:     path,
		Root:     root,
	}, warnings, nil
}

// buildNode converts a single tree-sitter node into an IRNode, recursing into children.
func (b *IRBuilder) buildNode(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]BuildWarning) *ir.IRNode {
	if node == nil {
		return nil
	}
	if node.IsError() || node.Type() == "ERROR" {
		// Skip ERROR subtree; emit a warning so the caller knows something was skipped.
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
	// Set text for leaf nodes
	if node.ChildCount() == 0 {
		irNode.Text = node.Content(source)
	}
	extractAttrs(irNode, node, source)
	irNode.Children = b.buildChildren(node, source, irNode, path, warnings)
	return irNode
}

// buildChildren iterates over all children and collects non-nil IRNodes.
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
	case "assignment", "augmented_assignment":
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
	}
}
