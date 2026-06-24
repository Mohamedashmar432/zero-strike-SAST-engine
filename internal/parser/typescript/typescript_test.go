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
