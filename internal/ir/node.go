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
	NodeKindAssert     NodeKind = "assert_statement"
	NodeKindKeywordArg NodeKind = "keyword_argument"
	NodeKindSwitch     NodeKind = "switch"
	NodeKindSelect     NodeKind = "select"
	NodeKindDefer      NodeKind = "defer"
	NodeKindUnknown    NodeKind = "unknown"
)

// ExceptHandler describes a single except clause of a try statement.
// Populated on the Try node's Attrs["except_handlers"] as []ExceptHandler.
type ExceptHandler struct {
	IsBare      bool     // true when the clause has no exception type (bare "except:")
	Types       []string // exception type names/expressions, empty when IsBare
	IsEmptyBody bool     // true when the handler body is just "pass"
}

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
