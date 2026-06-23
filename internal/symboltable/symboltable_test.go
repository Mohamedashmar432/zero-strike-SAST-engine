package symboltable_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/symboltable"
)

func TestDefineAndResolve(t *testing.T) {
	table := symboltable.NewBuilder().Build(&ir.IRFile{Root: &ir.IRNode{Kind: ir.NodeKindModule}})

	scope := table.ScopeAt(core.Location{StartLine: 1})
	table.Define(symboltable.Symbol{Name: "x", Kind: symboltable.SymbolVariable, Scope: scope})

	sym, ok := table.Resolve("x", scope.ID)
	if !ok {
		t.Fatal("expected to resolve x")
	}
	if sym.Name != "x" {
		t.Errorf("got name %q, want x", sym.Name)
	}
}

func TestResolve_Missing(t *testing.T) {
	table := symboltable.NewBuilder().Build(&ir.IRFile{Root: &ir.IRNode{Kind: ir.NodeKindModule}})
	scope := table.ScopeAt(core.Location{StartLine: 1})
	_, ok := table.Resolve("undefined", scope.ID)
	if ok {
		t.Fatal("expected resolve to fail for undefined symbol")
	}
}

func TestAllSymbols(t *testing.T) {
	table := symboltable.NewBuilder().Build(&ir.IRFile{Root: &ir.IRNode{Kind: ir.NodeKindModule}})
	scope := table.ScopeAt(core.Location{StartLine: 1})
	table.Define(symboltable.Symbol{Name: "a", Kind: symboltable.SymbolVariable, Scope: scope})
	table.Define(symboltable.Symbol{Name: "b", Kind: symboltable.SymbolVariable, Scope: scope})
	if len(table.AllSymbols()) != 2 {
		t.Errorf("expected 2 symbols, got %d", len(table.AllSymbols()))
	}
}

// TestBuildFromIR verifies the builder extracts symbols from a real Python IR.
func TestBuildFromIR(t *testing.T) {
	// Minimal IR: module → function_def "greet" → assignment "message"
	assignNode := &ir.IRNode{
		Kind:     ir.NodeKindAssignment,
		Location: core.Location{StartLine: 2, EndLine: 2},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "message", Location: core.Location{StartLine: 2}},
		},
	}
	funcNode := &ir.IRNode{
		Kind:     ir.NodeKindFunction,
		Location: core.Location{StartLine: 1, EndLine: 3},
		Attrs:    map[string]any{"function_name": "greet"},
		Children: []*ir.IRNode{assignNode},
	}
	assignNode.Parent = funcNode

	root := &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Location: core.Location{StartLine: 1, EndLine: 3},
		Children: []*ir.IRNode{funcNode},
	}
	funcNode.Parent = root

	irFile := &ir.IRFile{Language: core.LangPython, Path: "test.py", Root: root}
	table := symboltable.NewBuilder().Build(irFile)

	syms := table.AllSymbols()
	if len(syms) == 0 {
		t.Fatal("expected symbols, got none")
	}

	// greet should be a function symbol
	greet, ok := table.Resolve("greet", table.ScopeAt(core.Location{StartLine: 1}).ID)
	if !ok {
		t.Error("expected function symbol 'greet'")
	} else if greet.Kind != symboltable.SymbolFunction {
		t.Errorf("greet kind = %q, want function", greet.Kind)
	}
}

// TestScopeChain verifies that Resolve walks parent scopes.
func TestScopeChain(t *testing.T) {
	// module → function_def "outer" with assignment "x" inside
	assignNode := &ir.IRNode{
		Kind:     ir.NodeKindAssignment,
		Location: core.Location{StartLine: 2, EndLine: 2},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "x", Location: core.Location{StartLine: 2}},
		},
	}
	funcNode := &ir.IRNode{
		Kind:     ir.NodeKindFunction,
		Location: core.Location{StartLine: 1, EndLine: 5},
		Attrs:    map[string]any{"function_name": "outer"},
		Children: []*ir.IRNode{assignNode},
	}
	root := &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Location: core.Location{StartLine: 1, EndLine: 10},
		Children: []*ir.IRNode{funcNode},
	}

	irFile := &ir.IRFile{Language: core.LangPython, Path: "scope_test.py", Root: root}
	table := symboltable.NewBuilder().Build(irFile)

	// x is inside the function scope — look it up from that scope
	funcScope := table.ScopeAt(core.Location{StartLine: 3})
	x, ok := table.Resolve("x", funcScope.ID)
	if !ok {
		t.Error("expected to resolve 'x' from function scope")
	} else if x.Kind != symboltable.SymbolVariable {
		t.Errorf("x kind = %q, want variable", x.Kind)
	}
}
