package taint_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer/taint"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/symboltable"
)

// buildContext mirrors what analyzer.Analyze does, returning the full Result
// so the weak/strong tier can be inspected.
func buildContext(file *ir.IRFile) taint.Result {
	return taint.BuildContext(file, symboltable.NewBuilder().Build(file), nil)
}

// funcWithParams builds a function_def node carrying the parameter names the
// seeding walk reads off Attrs["parameters"].
func funcWithParams(params []string, body ...*ir.IRNode) *ir.IRNode {
	return &ir.IRNode{
		Kind:     ir.NodeKindFunction,
		Attrs:    map[string]any{"parameters": params},
		Children: body,
	}
}

// TestBuildContext_ParameterTaintIsWeak covers the distinction the whole
// precision change rests on: a bare parameter is tainted, but weakly, because
// nothing traced it to an untrusted source.
func TestBuildContext_ParameterTaintIsWeak(t *testing.T) {
	root := &ir.IRNode{
		Kind:     ir.NodeKindModule,
		Children: []*ir.IRNode{funcWithParams([]string{"path", "delay"})},
	}
	res := buildContext(&ir.IRFile{Root: root})

	for _, name := range []string{"path", "delay"} {
		if !res.Tainted[name] {
			t.Errorf("%s: expected tainted (parameter seeding must keep working)", name)
		}
		if !res.Weak[name] {
			t.Errorf("%s: expected weak, got strong", name)
		}
	}
}

// TestBuildContext_SourceTaintIsStrong is the other half: a matched source
// pattern must never be weak, or require_real_source would suppress genuine
// findings and recall would collapse.
func TestBuildContext_SourceTaintIsStrong(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("user_id", "request.args.get('id')", ident("_")),
		},
	}
	res := buildContext(&ir.IRFile{Root: root})

	if !res.Tainted["user_id"] {
		t.Fatal("expected user_id tainted from request.args source")
	}
	if res.Weak["user_id"] {
		t.Error("expected source-derived taint to be strong, got weak")
	}
}

// TestBuildContext_WeaknessPropagatesOneHop verifies that the tier follows the
// propagation edge rather than being recomputed: a value derived from a
// parameter is still only parameter-derived.
func TestBuildContext_WeaknessPropagatesOneHop(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			funcWithParams([]string{"path"}),
			assignment("url", "base + path", ident("path")),
		},
	}
	res := buildContext(&ir.IRFile{Root: root})

	if !res.Tainted["url"] {
		t.Fatal("expected url tainted by propagation from path")
	}
	if !res.Weak["url"] {
		t.Error("expected weakness to propagate from path to url")
	}
}

// TestBuildContext_StrengthPropagatesOneHop is the same edge in the other
// direction: once a real source is involved, everything downstream is strong.
func TestBuildContext_StrengthPropagatesOneHop(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("user_id", "request.args.get('id')", ident("_")),
			assignment("query", "'SELECT ' + user_id", ident("user_id")),
		},
	}
	res := buildContext(&ir.IRFile{Root: root})

	if !res.Tainted["query"] {
		t.Fatal("expected query tainted by propagation from user_id")
	}
	if res.Weak["query"] {
		t.Error("expected strength to propagate from user_id to query")
	}
}

// TestBuildContext_ReassignmentToSourceUpgradesWeakToStrong covers a parameter
// that is later overwritten from a real source. The tier must be recomputed,
// not left at its seeded value.
func TestBuildContext_ReassignmentToSourceUpgradesWeakToStrong(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			funcWithParams([]string{"target"}),
			assignment("target", "request.args.get('u')", ident("_")),
		},
	}
	res := buildContext(&ir.IRFile{Root: root})

	if !res.Tainted["target"] {
		t.Fatal("expected target tainted")
	}
	if res.Weak["target"] {
		t.Error("expected reassignment from a real source to clear weakness")
	}
}

// TestBuildContext_CleanReassignmentClearsWeak guards a map leak: an untainted
// overwrite must drop the name from Weak as well as from Tainted, or Weak
// stops being a subset of Tainted.
func TestBuildContext_CleanReassignmentClearsWeak(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			funcWithParams([]string{"name"}),
			assignment("name", "'literal'", ident("_")),
		},
	}
	res := buildContext(&ir.IRFile{Root: root})

	if res.Tainted["name"] {
		t.Fatal("expected clean reassignment to untaint name")
	}
	if res.Weak["name"] {
		t.Error("expected Weak to stay a subset of Tainted")
	}
}

// TestBuildContext_WeakIsSubsetOfTainted states the package invariant
// directly, so a future edit to the assignment walk cannot quietly break it.
func TestBuildContext_WeakIsSubsetOfTainted(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			funcWithParams([]string{"a", "b"}),
			assignment("c", "request.args.get('c')", ident("_")),
			assignment("d", "b", ident("b")),
			assignment("a", "'clean'", ident("_")),
		},
	}
	res := buildContext(&ir.IRFile{Root: root})

	for name := range res.Weak {
		if !res.Tainted[name] {
			t.Errorf("%s is in Weak but not in Tainted", name)
		}
	}
}
