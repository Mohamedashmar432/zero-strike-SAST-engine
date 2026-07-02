//go:build cgo

package typescript

import (
	"testing"

	"github.com/zerostrike/scanner/internal/ir"
)

const evalSrc = `const x = eval("1+1");`

func TestTypeScriptParser_Parse(t *testing.T) {
	p := New()
	result, err := p.Parse(t.Context(), []byte(evalSrc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if result.RootNode == nil {
		t.Fatal("expected non-nil root node")
	}
	if result.RootNode.IsError() {
		t.Errorf("root node is an error node")
	}
}

func TestTypeScriptBuilder_Build(t *testing.T) {
	b := NewIRBuilder()
	irFile, warnings, err := b.Build("test.ts", []byte(evalSrc))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(warnings) > 0 {
		t.Logf("build warnings: %v", warnings)
	}
	if irFile == nil || irFile.Root == nil {
		t.Fatal("expected non-nil IR file and root")
	}
	if len(irFile.Root.Children) == 0 {
		t.Error("expected IR root to have children")
	}
	if string(irFile.Language) != "typescript" {
		t.Errorf("Language = %q, want typescript", irFile.Language)
	}

	// Walk IR looking for a call node (eval()).
	callFound := false
	ir.Walk(irFile.Root, func(n *ir.IRNode) bool {
		if n.Kind == ir.NodeKindCall {
			callFound = true
		}
		return true
	})
	if !callFound {
		t.Error("expected at least one call node in IR for eval() source")
	}
}

// TestIRBuilder_PairKeywordArg verifies Sprint 12: object-literal properties
// map to NodeKindKeywordArg, same as the JS builder.
func TestIRBuilder_PairKeywordArg(t *testing.T) {
	src := []byte("https.request(url, {rejectUnauthorized: false});\n")
	builder := NewIRBuilder()
	irFile, _, err := builder.Build("test.ts", src)
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

// TestIRBuilder_EmptyCatchBlock verifies Sprint 12: an empty catch body is
// recorded as IsEmptyBody on the try node's except_handlers attr.
func TestIRBuilder_EmptyCatchBlock(t *testing.T) {
	src := []byte("try {\n  doThing();\n} catch (e) {\n}\n")
	builder := NewIRBuilder()
	irFile, _, err := builder.Build("test.ts", src)
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
