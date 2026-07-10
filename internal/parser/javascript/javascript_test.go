//go:build cgo

package javascript_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/javascript"
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

// TestIRBuilder_VariableDeclaratorIsAssignment is a regression test for a
// Sprint 12 QA finding: const/let/var declarations with an initializer
// produce a variable_declarator node (fields name/value), not
// assignment_expression (fields left/right). Before this fix,
// variable_declarator fell through to NodeKindUnknown, making every
// `const x = ...` / `let x = ...` invisible to both rule matching and taint
// tracking — the direct cause of near-zero findings on real-world JS/TS code,
// which almost always declares rather than reassigns.
func TestIRBuilder_VariableDeclaratorIsAssignment(t *testing.T) {
	src := []byte("const password = \"hunter2\";\n")
	builder := javascript.NewIRBuilder()
	irFile, _, err := builder.Build("test.js", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	assignments := ir.FindByKind(irFile.Root, ir.NodeKindAssignment)
	if len(assignments) != 1 {
		t.Fatalf("expected 1 assignment node for 'const password = ...', got %d", len(assignments))
	}
	lhs, _ := assignments[0].Attrs["lhs"].(string)
	rhs, _ := assignments[0].Attrs["rhs"].(string)
	if lhs != "password" {
		t.Errorf("lhs: got %q, want %q", lhs, "password")
	}
	if rhs != "\"hunter2\"" {
		t.Errorf("rhs: got %q, want %q", rhs, "\"hunter2\"")
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
