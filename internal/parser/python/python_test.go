package python_test

import (
	"context"
	"testing"

	"github.com/zerostrike/scanner/internal/ir"
	pythonparser "github.com/zerostrike/scanner/internal/parser/python"
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
