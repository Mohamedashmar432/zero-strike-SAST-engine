//go:build cgo

package html

import (
	"context"
	"fmt"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
)

// IRBuilder converts an HTML tree-sitter CST into an ir.IRFile.
type IRBuilder struct{}

// NewIRBuilder creates a new IRBuilder.
func NewIRBuilder() *IRBuilder { return &IRBuilder{} }

// Build parses source and produces a flat IRFile: the module root's children
// are one call node per HTML element (in document order), each call node being
// [tag-name identifier, keyword_argument per attribute]. Elements are NOT
// nested inside one another, so an element's attribute filters can never match
// a descendant element's attributes. Build never panics on malformed input.
func (b *IRBuilder) Build(path string, source []byte) (*ir.IRFile, []ir.BuildWarning, error) {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil, nil, fmt.Errorf("html builder: %w", err)
	}
	root := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindModule,
		Location: nodeLoc(result.RootNode, path),
		Attrs:    make(map[string]any),
	}
	var elems []*ir.IRNode
	collectElements(result.RootNode, source, path, root, &elems)
	root.Children = elems
	return &ir.IRFile{
		Language: core.LangHTML,
		Path:     path,
		Root:     root,
	}, nil, nil
}

// collectElements walks the CST and appends a call node for every element,
// script_element, and style_element it finds, recursing through all children so
// nested elements are collected too (flatly, onto the same output slice).
func collectElements(node *sitter.Node, source []byte, path string, parent *ir.IRNode, out *[]*ir.IRNode) {
	if node == nil {
		return
	}
	switch node.Type() {
	case "element", "script_element", "style_element":
		if call := buildElementCall(node, source, path, parent); call != nil {
			*out = append(*out, call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectElements(node.Child(i), source, path, parent, out)
	}
}

// buildElementCall builds the call IR node modeling one element: child[0] is the
// tag-name identifier (the callee), and each following child is a
// keyword_argument node carrying an attribute's name/value.
func buildElementCall(node *sitter.Node, source []byte, path string, parent *ir.IRNode) *ir.IRNode {
	tag := findTagNode(node)
	if tag == nil {
		return nil
	}
	tagName := ""
	var attrs []*sitter.Node
	for i := 0; i < int(tag.ChildCount()); i++ {
		c := tag.Child(i)
		switch c.Type() {
		case "tag_name":
			tagName = strings.ToLower(c.Content(source))
		case "attribute":
			attrs = append(attrs, c)
		}
	}
	if tagName == "" {
		return nil
	}
	call := &ir.IRNode{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindCall,
		Location: nodeLoc(node, path),
		Parent:   parent,
		Attrs:    map[string]any{"argument_count": len(attrs)},
	}
	children := []*ir.IRNode{{
		NodeID:   uuid.New().String(),
		Kind:     ir.NodeKindIdentifier,
		Text:     tagName,
		Location: nodeLoc(tag, path),
		Parent:   call,
	}}
	for _, a := range attrs {
		name, value := attrNameValue(a, source)
		children = append(children, &ir.IRNode{
			NodeID:   uuid.New().String(),
			Kind:     ir.NodeKindKeywordArg,
			Location: nodeLoc(a, path),
			Parent:   call,
			Attrs:    map[string]any{"kwarg_name": strings.ToLower(name), "kwarg_value": value},
		})
	}
	call.Children = children
	return call
}

// findTagNode returns an element's start_tag or self_closing_tag child.
func findTagNode(element *sitter.Node) *sitter.Node {
	for i := 0; i < int(element.ChildCount()); i++ {
		c := element.Child(i)
		if t := c.Type(); t == "start_tag" || t == "self_closing_tag" {
			return c
		}
	}
	return nil
}

// attrNameValue extracts an attribute node's name and (unquoted) value. A
// boolean attribute (e.g. `sandbox`) yields an empty value; an empty quoted
// value (e.g. `sandbox=""`) also yields an empty value.
func attrNameValue(attr *sitter.Node, source []byte) (string, string) {
	var name, value string
	for i := 0; i < int(attr.ChildCount()); i++ {
		c := attr.Child(i)
		switch c.Type() {
		case "attribute_name":
			name = c.Content(source)
		case "attribute_value":
			value = c.Content(source)
		case "quoted_attribute_value":
			value = quotedValue(c, source)
		}
	}
	return name, value
}

// quotedValue returns the inner text of a quoted_attribute_value node (the
// attribute_value child), or "" for an empty quoted value.
func quotedValue(q *sitter.Node, source []byte) string {
	for i := 0; i < int(q.ChildCount()); i++ {
		c := q.Child(i)
		if c.Type() == "attribute_value" {
			return c.Content(source)
		}
	}
	return ""
}

// nodeLoc converts a tree-sitter node's span to a 1-indexed-line core.Location.
func nodeLoc(n *sitter.Node, path string) core.Location {
	s := n.StartPoint()
	e := n.EndPoint()
	return core.Location{
		File:      path,
		StartLine: int(s.Row) + 1,
		StartCol:  int(s.Column),
		EndLine:   int(e.Row) + 1,
		EndCol:    int(e.Column),
	}
}

// ScriptBlock is one inline <script> body extracted from an HTML document,
// with the source position of the body's first character in the HTML file so
// findings from parsing it as JavaScript can be rebased to real HTML lines.
type ScriptBlock struct {
	JS        []byte
	StartLine int // 1-indexed line of the body's first character
	StartCol  int // 0-indexed column of the body's first character
}

// ExtractScripts returns the inline JavaScript bodies of a document's <script>
// elements. External scripts (with a src attribute) and non-JavaScript scripts
// (a type attribute that isn't a JS mimetype, e.g. application/json) are
// skipped — the former have no inline body, the latter aren't JavaScript.
func ExtractScripts(source []byte) []ScriptBlock {
	p := New()
	result, err := p.Parse(context.Background(), source)
	if err != nil {
		return nil
	}
	var blocks []ScriptBlock
	collectScripts(result.RootNode, source, &blocks)
	return blocks
}

func collectScripts(node *sitter.Node, source []byte, out *[]ScriptBlock) {
	if node == nil {
		return
	}
	if node.Type() == "script_element" {
		if blk, ok := scriptBlock(node, source); ok {
			*out = append(*out, blk)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectScripts(node.Child(i), source, out)
	}
}

func scriptBlock(node *sitter.Node, source []byte) (ScriptBlock, bool) {
	tag := findTagNode(node)
	if tag == nil {
		return ScriptBlock{}, false
	}
	for i := 0; i < int(tag.ChildCount()); i++ {
		c := tag.Child(i)
		if c.Type() != "attribute" {
			continue
		}
		name, value := attrNameValue(c, source)
		switch strings.ToLower(name) {
		case "src":
			return ScriptBlock{}, false // external script: no inline body
		case "type":
			if !isJSType(value) {
				return ScriptBlock{}, false
			}
		}
	}
	var raw *sitter.Node
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == "raw_text" {
			raw = node.Child(i)
			break
		}
	}
	if raw == nil {
		return ScriptBlock{}, false // empty <script></script>
	}
	s := raw.StartPoint()
	return ScriptBlock{
		JS:        []byte(raw.Content(source)),
		StartLine: int(s.Row) + 1,
		StartCol:  int(s.Column),
	}, true
}

// isJSType reports whether a <script> type attribute denotes JavaScript. An
// absent/empty type is JavaScript by default; "module" is an ES module.
func isJSType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "text/javascript", "application/javascript", "module", "text/ecmascript", "application/ecmascript":
		return true
	default:
		return false
	}
}
