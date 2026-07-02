//go:build cgo

package javascript_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/parser/javascript"
)

// TestIRBuilder_PairKeywordArg verifies Sprint 12: object-literal properties
// (used as JS's equivalent of keyword arguments) map to NodeKindKeywordArg.
func TestIRBuilder_PairKeywordArg(t *testing.T) {
	src := []byte("https.request(url, {rejectUnauthorized: false});\n")
	builder := javascript.NewIRBuilder()
	irFile, _, err := builder.Build("test.js", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	pairs := ir.FindByKind(irFile.Root, ir.NodeKindKeywordArg)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 keyword-arg (pair) node, got %d", len(pairs))
	}
	name, _ := pairs[0].Attrs["kwarg_name"].(string)
	value, _ := pairs[0].Attrs["kwarg_value"].(string)
	if name != "rejectUnauthorized" {
		t.Errorf("kwarg_name: got %q, want %q", name, "rejectUnauthorized")
	}
	if value != "false" {
		t.Errorf("kwarg_value: got %q, want %q", value, "false")
	}
}

// TestIRBuilder_AssignmentRHS verifies Sprint 12: assignment nodes capture the
// right-hand-side text in Attrs["rhs"].
func TestIRBuilder_AssignmentRHS(t *testing.T) {
	src := []byte("el.innerHTML = userInput;\n")
	builder := javascript.NewIRBuilder()
	irFile, _, err := builder.Build("test.js", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	assignments := ir.FindByKind(irFile.Root, ir.NodeKindAssignment)
	if len(assignments) != 1 {
		t.Fatalf("expected 1 assignment node, got %d", len(assignments))
	}
	rhs, _ := assignments[0].Attrs["rhs"].(string)
	if rhs != "userInput" {
		t.Errorf("rhs: got %q, want %q", rhs, "userInput")
	}
}

// TestIRBuilder_EmptyCatchBlock verifies Sprint 12: an empty catch body is
// recorded as IsEmptyBody on the try node's except_handlers attr.
func TestIRBuilder_EmptyCatchBlock(t *testing.T) {
	src := []byte("try {\n  doThing();\n} catch (e) {\n}\n")
	builder := javascript.NewIRBuilder()
	irFile, _, err := builder.Build("test.js", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	tries := ir.FindByKind(irFile.Root, ir.NodeKindTry)
	if len(tries) != 1 {
		t.Fatalf("expected 1 try node, got %d", len(tries))
	}
	handlers, _ := tries[0].Attrs["except_handlers"].([]ir.ExceptHandler)
	if len(handlers) != 1 {
		t.Fatalf("expected 1 catch handler, got %d", len(handlers))
	}
	if !handlers[0].IsEmptyBody {
		t.Error("expected IsEmptyBody=true for an empty catch block")
	}
}

// TestIRBuilder_NonEmptyCatchBlock verifies a catch block with a real
// statement is not flagged as empty.
func TestIRBuilder_NonEmptyCatchBlock(t *testing.T) {
	src := []byte("try {\n  doThing();\n} catch (e) {\n  console.error(e);\n}\n")
	builder := javascript.NewIRBuilder()
	irFile, _, err := builder.Build("test.js", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	tries := ir.FindByKind(irFile.Root, ir.NodeKindTry)
	if len(tries) != 1 {
		t.Fatalf("expected 1 try node, got %d", len(tries))
	}
	handlers, _ := tries[0].Attrs["except_handlers"].([]ir.ExceptHandler)
	if len(handlers) != 1 {
		t.Fatalf("expected 1 catch handler, got %d", len(handlers))
	}
	if handlers[0].IsEmptyBody {
		t.Error("expected IsEmptyBody=false for a catch block with a real statement")
	}
}
