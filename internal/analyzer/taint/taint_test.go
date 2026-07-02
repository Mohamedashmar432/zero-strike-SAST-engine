package taint_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer/taint"
	"github.com/zerostrike/scanner/internal/ir"
)

func assignment(lhs, rhs string, rhsNode *ir.IRNode) *ir.IRNode {
	return &ir.IRNode{
		Kind:     ir.NodeKindAssignment,
		Attrs:    map[string]any{"lhs": lhs, "rhs": rhs},
		Children: []*ir.IRNode{{Kind: ir.NodeKindIdentifier, Text: lhs}, rhsNode},
	}
}

func ident(name string) *ir.IRNode {
	return &ir.IRNode{Kind: ir.NodeKindIdentifier, Text: name}
}

func TestBuild_NilFile(t *testing.T) {
	if got := taint.Build(nil); len(got) != 0 {
		t.Errorf("expected empty set for nil file, got %v", got)
	}
}

func TestBuild_SourceExpressionTaintsVariable(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("user_id", "request.args.get('id')", ident("_")),
		},
	}
	tainted := taint.Build(&ir.IRFile{Root: root})
	if !tainted["user_id"] {
		t.Error("expected user_id to be tainted from request.args source")
	}
}

func TestBuild_PropagatesThroughReassignment(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("user_id", "request.args.get('id')", ident("_")),
			assignment("query", "\"SELECT \" + user_id", ident("user_id")),
		},
	}
	tainted := taint.Build(&ir.IRFile{Root: root})
	if !tainted["query"] {
		t.Error("expected query to be tainted via propagation from user_id")
	}
}

func TestBuild_ExpressSourceTaintsVariable(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("userInput", "req.query.name", ident("_")),
		},
	}
	tainted := taint.Build(&ir.IRFile{Root: root})
	if !tainted["userInput"] {
		t.Error("expected userInput to be tainted from req.query source")
	}
}

func TestBuild_LocationSourceTaintsVariable(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("hash", "window.location.hash", ident("_")),
		},
	}
	tainted := taint.Build(&ir.IRFile{Root: root})
	if !tainted["hash"] {
		t.Error("expected hash to be tainted from window.location source")
	}
}

func TestBuild_UnrelatedAssignmentNotTainted(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("user_id", "request.args.get('id')", ident("_")),
			assignment("greeting", "\"hello\"", &ir.IRNode{Kind: ir.NodeKindLiteral, Text: "hello"}),
		},
	}
	tainted := taint.Build(&ir.IRFile{Root: root})
	if tainted["greeting"] {
		t.Error("expected greeting (constant literal) to not be tainted")
	}
}
