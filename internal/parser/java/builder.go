//go:build cgo

package java

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
)

// IRBuilder converts a Java tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// Build parses source and walks the resulting CST to produce an IRFile.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("java builder: %w", err)
	}
	var warnings []ir.BuildWarning
	root := b.buildNode(result.RootNode, source, nil, path, &warnings)
	return &ir.IRFile{
		Language: core.LangJava,
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
	// method_invocation and object_creation_expression carry their callee
	// (object+method, or constructor type) as separate named fields rather
	// than a nested selector/member-access child the way Go/PHP/C# do — so
	// calleeText()'s "first identifier/attribute child" walk in the engine
	// would otherwise only ever see the receiver ("Cipher"), never the
	// dotted form ("Cipher.getInstance") the rule YAML matches against.
	// ponytail: synthesize the same attribute-chain shape those other
	// languages get for free; revisit only if a future rule needs the
	// object expression itself walked (e.g. a chained call receiver).
	switch node.Type() {
	case "method_invocation":
		return b.buildMethodInvocation(node, source, parent, path, warnings)
	case "object_creation_expression":
		return b.buildObjectCreation(node, source, parent, path, warnings)
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

// buildMethodInvocation builds a call node whose first child is a synthetic
// attribute (object + method name) when the invocation has a receiver
// (Cipher.getInstance(...)), or a plain identifier when it's a bare call
// (getInstance(...)) — see the buildNode comment for why this is synthesized
// rather than inherited from the grammar shape directly.
func (b *IRBuilder) buildMethodInvocation(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning) *ir.IRNode {
	loc := nodeLocation(node)
	irNode := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindCall,
		Location: loc,
		Parent:   parent,
		Attrs:    make(map[string]any),
	}
	nameField := node.ChildByFieldName("name")
	nameIdent := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindIdentifier,
		Parent:   irNode,
		Attrs:    make(map[string]any),
		Location: loc,
	}
	if nameField != nil {
		nameIdent.Text = nameField.Content(source)
	}

	var calleeChild *ir.IRNode
	if objField := node.ChildByFieldName("object"); objField != nil {
		objNode := b.buildNode(objField, source, nil, path, warnings)
		attr := &ir.IRNode{
			NodeID:   uuid.New().String(),
			Kind:     ir.NodeKindAttribute,
			Parent:   irNode,
			Attrs:    make(map[string]any),
			Location: loc,
		}
		if objNode != nil {
			objNode.Parent = attr
			attr.Children = append(attr.Children, objNode)
		}
		nameIdent.Parent = attr
		attr.Children = append(attr.Children, nameIdent)
		calleeChild = attr
	} else {
		calleeChild = nameIdent
	}

	args, argCount := b.buildArguments(node.ChildByFieldName("arguments"), source, irNode, path, warnings)
	irNode.Children = append([]*ir.IRNode{calleeChild}, args...)
	irNode.Attrs["argument_count"] = argCount
	return irNode
}

// buildObjectCreation builds a call node for "new Type(...)" whose callee is
// the constructed type name (e.g. "DESKeySpec"), matching how BinaryFormatter
// (C#) and other "flag the risky type itself" rules already key on a bare
// constructor/type name rather than a dotted path.
func (b *IRBuilder) buildObjectCreation(node *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning) *ir.IRNode {
	loc := nodeLocation(node)
	irNode := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindCall,
		Location: loc,
		Parent:   parent,
		Attrs:    make(map[string]any),
	}
	typeIdent := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindIdentifier,
		Text:     typeText(node.ChildByFieldName("type"), source),
		Parent:   irNode,
		Attrs:    make(map[string]any),
		Location: loc,
	}
	args, argCount := b.buildArguments(node.ChildByFieldName("arguments"), source, irNode, path, warnings)
	irNode.Children = append([]*ir.IRNode{typeIdent}, args...)
	irNode.Attrs["argument_count"] = argCount
	return irNode
}

// buildArguments builds an argument_list's children and counts real
// arguments (excluding the "(" "," ")" tokens), matching the
// argument_count convention used by every other language builder.
func (b *IRBuilder) buildArguments(argsNode *sitter.Node, source []byte, parent *ir.IRNode, path string, warnings *[]ir.BuildWarning) ([]*ir.IRNode, int) {
	if argsNode == nil {
		return nil, 0
	}
	var children []*ir.IRNode
	count := 0
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		c := argsNode.Child(i)
		if built := b.buildNode(c, source, parent, path, warnings); built != nil {
			children = append(children, built)
		}
		if t := c.Type(); t != "," && t != "(" && t != ")" {
			count++
		}
	}
	return children, count
}

// typeText returns the constructed type's name, unwrapping a generic_type
// (new ArrayList<String>()) to its base type_identifier.
func typeText(n *sitter.Node, source []byte) string {
	if n == nil {
		return ""
	}
	if n.Type() == "generic_type" {
		if t := childOfType(n, "type_identifier"); t != nil {
			return t.Content(source)
		}
	}
	return n.Content(source)
}

func nodeLocation(node *sitter.Node) core.Location {
	start := node.StartPoint()
	end := node.EndPoint()
	return core.Location{
		StartLine: int(start.Row) + 1,
		StartCol:  int(start.Column),
		EndLine:   int(end.Row) + 1,
		EndCol:    int(end.Column),
	}
}

func mapKind(nodeType string) ir.NodeKind {
	switch nodeType {
	case "program":
		return ir.NodeKindModule
	case "class_declaration", "interface_declaration", "enum_declaration", "record_declaration":
		return ir.NodeKindClass
	case "method_declaration", "constructor_declaration", "lambda_expression":
		return ir.NodeKindFunction
	case "assignment_expression", "variable_declarator":
		return ir.NodeKindAssignment
	case "import_declaration":
		return ir.NodeKindImport
	case "identifier", "type_identifier":
		return ir.NodeKindIdentifier
	case "field_access":
		return ir.NodeKindAttribute
	case "string_literal", "character_literal", "decimal_integer_literal",
		"hex_integer_literal", "octal_integer_literal", "binary_integer_literal",
		"decimal_floating_point_literal", "hex_floating_point_literal",
		"true", "false", "null_literal":
		return ir.NodeKindLiteral
	case "block":
		return ir.NodeKindBlock
	case "return_statement":
		return ir.NodeKindReturn
	case "if_statement":
		return ir.NodeKindIf
	case "for_statement", "enhanced_for_statement":
		return ir.NodeKindFor
	case "while_statement", "do_statement":
		return ir.NodeKindWhile
	case "try_statement", "try_with_resources_statement":
		return ir.NodeKindTry
	case "binary_expression":
		return ir.NodeKindBinaryOp
	default:
		// ponytail: constructs no Sprint-17 rule needs (generics, annotations,
		// switch expressions, ...) fall through to Unknown rather than growing
		// the switch speculatively. Add a case when a rule needs one.
		return ir.NodeKindUnknown
	}
}

func extractAttrs(n *ir.IRNode, node *sitter.Node, source []byte) {
	switch node.Type() {
	case "assignment_expression":
		if lhs := node.ChildByFieldName("left"); lhs != nil {
			n.Attrs["lhs"] = lhs.Content(source)
		}
		if rhs := node.ChildByFieldName("right"); rhs != nil {
			n.Attrs["rhs"] = rhs.Content(source)
		}
		if op := node.ChildByFieldName("operator"); op != nil && op.Content(source) != "=" {
			// Compound assignment (x += y) keeps x's previous value flowing
			// into the result; the taint pass treats it as taint-preserving.
			n.Attrs["augmented"] = true
		}
	case "variable_declarator":
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["lhs"] = name.Content(source)
		}
		if value := node.ChildByFieldName("value"); value != nil {
			n.Attrs["rhs"] = value.Content(source)
		}
	case "method_declaration", "constructor_declaration":
		if name := node.ChildByFieldName("name"); name != nil {
			n.Attrs["function_name"] = name.Content(source)
		}
		if params := extractParameters(node, source); len(params) > 0 {
			n.Attrs["parameters"] = params
		}
	case "return_statement":
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
// method/constructor declaration into a string slice.
func extractParameters(node *sitter.Node, source []byte) []string {
	params := node.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var out []string
	for i := 0; i < int(params.ChildCount()); i++ {
		p := params.Child(i)
		if p.Type() != "formal_parameter" && p.Type() != "spread_parameter" {
			continue
		}
		if name := p.ChildByFieldName("name"); name != nil {
			out = append(out, name.Content(source))
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
