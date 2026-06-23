package ir

import "github.com/zerostrike/scanner/internal/core"

// NodeKind identifies the kind of an IR node.
type NodeKind string

const (
	NodeKindModule     NodeKind = "module"
	NodeKindFunction   NodeKind = "function_def"
	NodeKindClass      NodeKind = "class_def"
	NodeKindCall       NodeKind = "call"
	NodeKindAssignment NodeKind = "assignment"
	NodeKindImport     NodeKind = "import"
	NodeKindLiteral    NodeKind = "literal"
	NodeKindIdentifier NodeKind = "identifier"
	NodeKindBlock      NodeKind = "block"
	NodeKindReturn     NodeKind = "return"
	NodeKindIf         NodeKind = "if"
	NodeKindFor        NodeKind = "for"
	NodeKindWhile      NodeKind = "while"
	NodeKindTry        NodeKind = "try"
	NodeKindAttribute  NodeKind = "attribute"
	NodeKindBinaryOp   NodeKind = "binary_op"
	NodeKindUnknown    NodeKind = "unknown"
)

// IRNode is a node in the ZeroStrike Intermediate Representation.
// The NodeID is a stable UUID assigned at construction time,
// allowing graph layers (CFG, DFG, call graph) to reference nodes by ID.
type IRNode struct {
	NodeID   string
	Kind     NodeKind
	Text     string
	Location core.Location
	Children []*IRNode
	Parent   *IRNode
	Attrs    map[string]any
}
