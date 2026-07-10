package symboltable_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/symboltable"
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

// TestBuildFromIR_ParametersBecomeSymbols verifies that parameter names
// captured by the builders in Attrs["parameters"] are defined as
// SymbolParameter in the function's own scope (and not in the global scope).
func TestBuildFromIR_ParametersBecomeSymbols(t *testing.T) {
	funcNode := &ir.IRNode{
		Kind:     ir.NodeKindFunction,
		Location: core.Location{StartLine: 1, EndLine: 3},
		Attrs: map[string]any{
			"function_name": "greet",
			"parameters":    []string{"name", "greeting"},
		},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindBlock, Location: core.Location{StartLine: 2, EndLine: 3}},
		},
	}
	root := &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Location: core.Location{StartLine: 1, EndLine: 5},
		Children: []*ir.IRNode{funcNode},
	}
	table := symboltable.NewBuilder().Build(&ir.IRFile{Language: core.LangPython, Path: "test.py", Root: root})

	// Resolvable from inside the function body.
	inner := table.ScopeAt(core.Location{StartLine: 2})
	sym, ok := table.Resolve("name", inner.ID)
	if !ok {
		t.Fatal("expected parameter symbol 'name' to resolve inside the function")
	}
	if sym.Kind != symboltable.SymbolParameter {
		t.Errorf("name kind = %q, want %q", sym.Kind, symboltable.SymbolParameter)
	}
	if sym.Scope.Type != symboltable.ScopeFunction {
		t.Errorf("name scope type = %q, want function", sym.Scope.Type)
	}

	// Not resolvable from module scope (line 5 is outside the function).
	outer := table.ScopeAt(core.Location{StartLine: 5})
	if _, ok := table.Resolve("greeting", outer.ID); ok {
		t.Error("expected parameter 'greeting' to NOT resolve from module scope")
	}
}

// TestClassScope_MethodBodyExclusion verifies Python LEGB: class scope is not in the
// lookup chain for method bodies. A class-level assignment must NOT be resolved from
// inside a method.
func TestClassScope_MethodBodyExclusion(t *testing.T) {
	// class Foo:        # line 1
	//     cls_var = 1   # line 2
	//     def method(self): # line 3
	//         pass      # line 4
	clsVarAssign := &ir.IRNode{
		Kind:     ir.NodeKindAssignment,
		Location: core.Location{StartLine: 2, EndLine: 2},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "cls_var", Location: core.Location{StartLine: 2}},
		},
	}
	methodNode := &ir.IRNode{
		Kind:     ir.NodeKindFunction,
		Location: core.Location{StartLine: 3, EndLine: 4},
		Attrs:    map[string]any{"function_name": "method"},
	}
	classNode := &ir.IRNode{
		Kind:     ir.NodeKindClass,
		Location: core.Location{StartLine: 1, EndLine: 4},
		Children: []*ir.IRNode{clsVarAssign, methodNode},
	}
	root := &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Location: core.Location{StartLine: 1, EndLine: 10},
		Children: []*ir.IRNode{classNode},
	}

	table := symboltable.NewBuilder().Build(&ir.IRFile{Language: core.LangPython, Path: "cls.py", Root: root})

	methodScope := table.ScopeAt(core.Location{StartLine: 3})
	_, found := table.Resolve("cls_var", methodScope.ID)
	if found {
		t.Error("cls_var must not be visible inside method body (Python LEGB excludes class scope)")
	}
}

// TestComprehensionScope_VariableIsolation verifies that Resolve does not walk DOWN
// into child scopes. A symbol defined only in a comprehension scope must not be
// found when resolving from the enclosing scope.
func TestComprehensionScope_VariableIsolation(t *testing.T) {
	table := symboltable.NewBuilder().Build(&ir.IRFile{Root: &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Location: core.Location{StartLine: 1, EndLine: 10},
	}})

	globalScope := table.ScopeAt(core.Location{StartLine: 1})

	// ponytail: builder does not yet emit comprehension scopes; this tests Resolve semantics only.
	// Simulate comprehension scope as a child (ScopeBlock proxy) and verify it doesn't leak.
	compScope := symboltable.Scope{ID: "comp-scope-1", ParentID: globalScope.ID, Type: symboltable.ScopeBlock}
	table.Define(symboltable.Symbol{Name: "i", Kind: symboltable.SymbolVariable, Scope: compScope})

	_, found := table.Resolve("i", globalScope.ID)
	if found {
		t.Error("comprehension loop variable must not be visible in enclosing scope (Resolve walks up, not down)")
	}
}

// TestGlobalNonlocal_ScopeRebinding verifies that symbols in an outer function scope
// are visible inside a nested function (the nonlocal use case), and that the scope
// chain walk reaches them correctly.
func TestGlobalNonlocal_ScopeRebinding(t *testing.T) {
	// def outer():    # line 1
	//     result = 0  # line 2
	//     def inner():# line 3
	//         pass    # line 4  ← resolve "result" should reach outer's scope
	outerAssign := &ir.IRNode{
		Kind:     ir.NodeKindAssignment,
		Location: core.Location{StartLine: 2, EndLine: 2},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindIdentifier, Text: "result", Location: core.Location{StartLine: 2}},
		},
	}
	innerFunc := &ir.IRNode{
		Kind:     ir.NodeKindFunction,
		Location: core.Location{StartLine: 3, EndLine: 4},
		Attrs:    map[string]any{"function_name": "inner"},
	}
	outerFunc := &ir.IRNode{
		Kind:     ir.NodeKindFunction,
		Location: core.Location{StartLine: 1, EndLine: 4},
		Attrs:    map[string]any{"function_name": "outer"},
		Children: []*ir.IRNode{outerAssign, innerFunc},
	}
	root := &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Location: core.Location{StartLine: 1, EndLine: 10},
		Children: []*ir.IRNode{outerFunc},
	}

	table := symboltable.NewBuilder().Build(&ir.IRFile{Language: core.LangPython, Path: "nonlocal.py", Root: root})

	innerScope := table.ScopeAt(core.Location{StartLine: 4})
	sym, found := table.Resolve("result", innerScope.ID)
	if !found {
		t.Error("nonlocal: 'result' from outer scope must be visible inside inner function via scope chain")
	} else if sym.Name != "result" {
		t.Errorf("expected symbol name 'result', got %q", sym.Name)
	}
}

// TestWalrus_BoundsToEnclosingScope verifies that a walrus-assigned variable is
// resolvable from the enclosing (function/module) scope. The SymbolTable must find
// symbols defined in the same scope they were Define'd into.
// ponytail: builder does not yet emit walrus nodes; this tests Define+Resolve semantics.
func TestWalrus_BoundsToEnclosingScope(t *testing.T) {
	table := symboltable.NewBuilder().Build(&ir.IRFile{Root: &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Location: core.Location{StartLine: 1, EndLine: 10},
	}})

	enclosingScope := table.ScopeAt(core.Location{StartLine: 1})
	// Walrus `:=` inside a comprehension binds to the enclosing scope, not the comp scope.
	table.Define(symboltable.Symbol{Name: "y", Kind: symboltable.SymbolVariable, Scope: enclosingScope})

	_, found := table.Resolve("y", enclosingScope.ID)
	if !found {
		t.Error("walrus-assigned variable must be resolvable from the enclosing scope")
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
