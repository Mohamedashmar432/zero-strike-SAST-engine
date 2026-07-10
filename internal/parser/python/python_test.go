//go:build cgo

package python_test

import (
	"context"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	pythonparser "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/python"
)

func TestParse_BasicModule(t *testing.T) {
	src := []byte(`
def hello(name):
    return "Hello, " + name

result = hello("world")
print(result)
`)
	p := pythonparser.New()
	result, err := p.Parse(context.Background(), src)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if result.RootNode == nil {
		t.Fatal("RootNode is nil")
	}
	if result.RootNode.Type() != "module" {
		t.Errorf("root type: got %q, want %q", result.RootNode.Type(), "module")
	}
}

func TestIRBuilder_BasicModule(t *testing.T) {
	src := []byte(`
def hello(name):
    return "Hello, " + name

result = hello("world")
eval(result)
`)
	p := pythonparser.New()
	parseResult, err := p.Parse(context.Background(), src)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	builder := pythonparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.py", parseResult.Source)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if irFile.Root == nil {
		t.Fatal("IRFile root is nil")
	}
	if irFile.Root.Kind != ir.NodeKindModule {
		t.Errorf("root kind: got %q, want module", irFile.Root.Kind)
	}

	// Verify all nodes have non-empty NodeIDs
	var emptyIDs int
	ir.Walk(irFile.Root, func(n *ir.IRNode) bool {
		if n.NodeID == "" {
			emptyIDs++
		}
		return true
	})
	if emptyIDs > 0 {
		t.Errorf("found %d nodes with empty NodeID", emptyIDs)
	}

	// Verify function defs detected
	funcs := ir.FindByKind(irFile.Root, ir.NodeKindFunction)
	if len(funcs) == 0 {
		t.Error("no function_def nodes found")
	}

	// Verify call nodes detected
	calls := ir.FindByKind(irFile.Root, ir.NodeKindCall)
	if len(calls) == 0 {
		t.Error("no call nodes found")
	}

	// Verify FindCalls finds eval()
	evalCalls := ir.FindCalls(irFile.Root, "eval")
	if len(evalCalls) == 0 {
		t.Error("eval() call not found")
	}
}

// TestIRBuilder_MalformedFile verifies C5: a file with a syntax error must not panic,
// must emit at least one BuildWarning, and must still yield IR nodes from valid portions.
func TestIRBuilder_MalformedFile(t *testing.T) {
	// Valid function followed by a syntax error, then another valid call.
	src := []byte(`
def greet(name):
    return "hello"

def (  # syntax error: missing function name

greet("world")
`)
	builder := pythonparser.NewIRBuilder()
	irFile, warnings, err := builder.Build("malformed.py", src)
	if err != nil {
		t.Fatalf("Build must not return error for syntax errors: %v", err)
	}
	if irFile == nil {
		t.Fatal("IRFile must not be nil for partially malformed input")
	}
	if len(warnings) == 0 {
		t.Error("expected at least one BuildWarning for malformed input, got none")
	}
	// Valid portions should still produce nodes.
	if irFile.Root == nil {
		t.Fatal("IRFile root must not be nil")
	}
}

// TestIRBuilder_KeywordArgument verifies Sprint 11: keyword_argument nodes map
// to NodeKindKeywordArg with kwarg_name/kwarg_value attrs captured.
func TestIRBuilder_KeywordArgument(t *testing.T) {
	src := []byte("app.run(debug=True)\n")
	builder := pythonparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.py", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	kwargs := ir.FindByKind(irFile.Root, ir.NodeKindKeywordArg)
	if len(kwargs) != 1 {
		t.Fatalf("expected 1 keyword_argument node, got %d", len(kwargs))
	}
	name, _ := kwargs[0].Attrs["kwarg_name"].(string)
	value, _ := kwargs[0].Attrs["kwarg_value"].(string)
	if name != "debug" {
		t.Errorf("kwarg_name: got %q, want %q", name, "debug")
	}
	if value != "True" {
		t.Errorf("kwarg_value: got %q, want %q", value, "True")
	}
}

// TestIRBuilder_AssignmentRHS verifies Sprint 11: assignment nodes capture the
// right-hand-side text in Attrs["rhs"].
func TestIRBuilder_AssignmentRHS(t *testing.T) {
	src := []byte("DEBUG = True\n")
	builder := pythonparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.py", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	assignments := ir.FindByKind(irFile.Root, ir.NodeKindAssignment)
	if len(assignments) != 1 {
		t.Fatalf("expected 1 assignment node, got %d", len(assignments))
	}
	rhs, _ := assignments[0].Attrs["rhs"].(string)
	if rhs != "True" {
		t.Errorf("rhs: got %q, want %q", rhs, "True")
	}
}

// TestIRBuilder_BareExcept verifies Sprint 11: a bare "except:" clause is
// recorded as IsBare on the try node's except_handlers attr.
func TestIRBuilder_BareExcept(t *testing.T) {
	src := []byte("try:\n    do_thing()\nexcept:\n    pass\n")
	builder := pythonparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.py", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	tries := ir.FindByKind(irFile.Root, ir.NodeKindTry)
	if len(tries) != 1 {
		t.Fatalf("expected 1 try node, got %d", len(tries))
	}
	handlers, _ := tries[0].Attrs["except_handlers"].([]ir.ExceptHandler)
	if len(handlers) != 1 {
		t.Fatalf("expected 1 except handler, got %d", len(handlers))
	}
	if !handlers[0].IsBare {
		t.Error("expected IsBare=true for bare except:")
	}
	if !handlers[0].IsEmptyBody {
		t.Error("expected IsEmptyBody=true for pass-only body")
	}
}

// TestIRBuilder_TypedExceptNotBare verifies a typed, non-empty except handler
// is recorded as neither bare nor empty.
func TestIRBuilder_TypedExceptNotBare(t *testing.T) {
	src := []byte("try:\n    do_thing()\nexcept ValueError:\n    log(e)\n")
	builder := pythonparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.py", src)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	tries := ir.FindByKind(irFile.Root, ir.NodeKindTry)
	if len(tries) != 1 {
		t.Fatalf("expected 1 try node, got %d", len(tries))
	}
	handlers, _ := tries[0].Attrs["except_handlers"].([]ir.ExceptHandler)
	if len(handlers) != 1 {
		t.Fatalf("expected 1 except handler, got %d", len(handlers))
	}
	if handlers[0].IsBare {
		t.Error("expected IsBare=false for except ValueError:")
	}
	if handlers[0].IsEmptyBody {
		t.Error("expected IsEmptyBody=false for a handler with a real statement")
	}
	if len(handlers[0].Types) != 1 || handlers[0].Types[0] != "ValueError" {
		t.Errorf("expected Types=[ValueError], got %v", handlers[0].Types)
	}
}
