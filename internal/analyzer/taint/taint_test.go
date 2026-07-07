package taint_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer/taint"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/ir"
	"github.com/zerostrike/scanner/internal/symboltable"
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

// build runs taint.Build with a symbol table derived from the same file,
// mirroring what analyzer.Analyze does.
func build(file *ir.IRFile) map[string]bool {
	return taint.Build(file, symboltable.NewBuilder().Build(file))
}

func TestBuild_NilFile(t *testing.T) {
	if got := taint.Build(nil, nil); len(got) != 0 {
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
	tainted := build(&ir.IRFile{Root: root})
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
	tainted := build(&ir.IRFile{Root: root})
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
	tainted := build(&ir.IRFile{Root: root, Language: core.LangJavaScript})
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
	tainted := build(&ir.IRFile{Root: root, Language: core.LangTypeScript})
	if !tainted["hash"] {
		t.Error("expected hash to be tainted from window.location source")
	}
}

func TestBuild_CSharpSourceTaintsVariable(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("cmd", "Request.QueryString[\"cmd\"]", ident("_")),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangCSharp})
	if !tainted["cmd"] {
		t.Error("expected cmd to be tainted from Request.QueryString source")
	}
}

// TestBuild_CSharpIndexerSourceTaintsVariable is a regression test for the
// Sprint 24 fix: HttpRequest's indexer form (Request["key"]) is equally
// untrusted as the explicit Request.QueryString[...] property form, but the
// old pattern only recognized the latter — confirmed missing on the real
// OWASP.WebGoat.NET app's context.Request["query"] usage.
func TestBuild_CSharpIndexerSourceTaintsVariable(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("query", "context.Request[\"query\"]", ident("_")),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangCSharp})
	if !tainted["query"] {
		t.Error("expected query to be tainted from the Request[...] indexer source")
	}
}

func TestBuild_GoSourceTaintsVariable(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("cmd", "os.Args[1]", ident("_")),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangGo})
	if !tainted["cmd"] {
		t.Error("expected cmd to be tainted from os.Args source")
	}
}

// TestBuild_GoSSRFSourceTaintsVariable_NonRReceiver is a regression test for
// the Sprint 24 fix: the old goPatterns.Sources regex anchored on a literal
// "r." receiver (`r\.URL\.Query\(\)`), missing the equally common shape where
// the *http.Request isn't the receiver itself, e.g. resp.Request.URL.Query().
func TestBuild_GoSSRFSourceTaintsVariable_NonRReceiver(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("target", "resp.Request.URL.Query().Get(\"url\")", ident("_")),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangGo})
	if !tainted["target"] {
		t.Error("expected target to be tainted from resp.Request.URL.Query() source (non-\"r.\" receiver)")
	}
}

func TestBuild_PHPSourceTaintsVariable(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("$id", "$_GET['id']", ident("_")),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPHP})
	if !tainted["$id"] {
		t.Error("expected $id to be tainted from $_GET source")
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
	tainted := build(&ir.IRFile{Root: root})
	if tainted["greeting"] {
		t.Error("expected greeting (constant literal) to not be tainted")
	}
}

// TestBuild_SanitizerClearsTaint: x = request...; x = html.escape(x) —
// the sanitizer call clears x's taint even though its argument is tainted.
func TestBuild_SanitizerClearsTaint(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("x", "request.args.get('y')", ident("_")),
			assignment("x", "html.escape(x)", &ir.IRNode{
				Kind:     ir.NodeKindCall,
				Children: []*ir.IRNode{ident("escape"), ident("x")},
			}),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPython})
	if tainted["x"] {
		t.Error("expected x to NOT be tainted after html.escape() sanitizer")
	}
}

// TestBuild_ReassignmentToCleanLiteralClearsTaint is the regression test for
// the never-clears bug: previously the tainted map was only ever set true,
// so x stayed tainted after an unrelated clean reassignment.
func TestBuild_ReassignmentToCleanLiteralClearsTaint(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("x", "request.args.get('y')", ident("_")),
			assignment("x", "\"literal\"", &ir.IRNode{Kind: ir.NodeKindLiteral, Text: "literal"}),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPython})
	if tainted["x"] {
		t.Error("expected x to NOT be tainted after reassignment to a clean literal")
	}
}

// TestBuild_AugmentedAssignmentPreservesTaint: x += "suffix" keeps x's prior
// value flowing into the result, so prior taint survives the fresh verdict.
func TestBuild_AugmentedAssignmentPreservesTaint(t *testing.T) {
	aug := assignment("x", "\" suffix\"", &ir.IRNode{Kind: ir.NodeKindLiteral, Text: " suffix"})
	aug.Attrs["augmented"] = true
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("x", "request.args.get('y')", ident("_")),
			aug,
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPython})
	if !tainted["x"] {
		t.Error("expected x to stay tainted after augmented assignment with clean RHS")
	}
}

// TestBuild_SameFilePassThroughFunctionTaints: a helper returning its own
// parameter unchanged, called with a tainted argument, taints the variable
// receiving its return value.
func TestBuild_SameFilePassThroughFunctionTaints(t *testing.T) {
	fn := &ir.IRNode{
		Kind:  ir.NodeKindFunction,
		Attrs: map[string]any{"function_name": "passthrough", "parameters": []string{"v"}},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindReturn, Attrs: map[string]any{"return_expr": "v"}},
		},
	}
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			fn,
			assignment("x", "request.args.get('id')", ident("_")),
			assignment("y", "passthrough(x)", &ir.IRNode{
				Kind:     ir.NodeKindCall,
				Children: []*ir.IRNode{ident("passthrough"), ident("x")},
			}),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPython})
	if !tainted["y"] {
		t.Error("expected y to be tainted via same-file pass-through function")
	}
}

// TestBuild_SameFileAlwaysTaintedFunctionTaints: a helper whose return value
// is itself a source taints its call sites even with no tainted arguments.
// This is the case only the function-summary pass can catch (no tainted
// identifier appears anywhere in the assignment's RHS).
func TestBuild_SameFileAlwaysTaintedFunctionTaints(t *testing.T) {
	fn := &ir.IRNode{
		Kind:  ir.NodeKindFunction,
		Attrs: map[string]any{"function_name": "get_user"},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindReturn, Attrs: map[string]any{"return_expr": "request.args.get('id')"}},
		},
	}
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			fn,
			assignment("y", "get_user()", &ir.IRNode{
				Kind:     ir.NodeKindCall,
				Children: []*ir.IRNode{ident("get_user")},
			}),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPython})
	if !tainted["y"] {
		t.Error("expected y to be tainted via always-tainted same-file function")
	}
}

// TestBuild_CleanHelperCallDoesNotTaint: calling a same-file helper that
// neither passes a parameter through nor returns a source, with clean
// arguments, must not taint the result.
func TestBuild_CleanHelperCallDoesNotTaint(t *testing.T) {
	fn := &ir.IRNode{
		Kind:  ir.NodeKindFunction,
		Attrs: map[string]any{"function_name": "constant", "parameters": []string{"v"}},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindReturn, Attrs: map[string]any{"return_expr": "42"}},
		},
	}
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			fn,
			assignment("n", "constant(seed)", &ir.IRNode{
				Kind:     ir.NodeKindCall,
				Children: []*ir.IRNode{ident("constant"), ident("seed")},
			}),
		},
	}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPython})
	if tainted["n"] {
		t.Error("expected n to NOT be tainted by a clean helper call with clean args")
	}
}

// TestBuild_CrossFunctionNameReuseNotContaminated: a same-named local in a
// different function is not left tainted by the summary/propagation logic.
// (Ceiling note: the map is file-scoped and flow-insensitive — the LAST
// assignment to a name in source order decides its final verdict, so the
// clean reassignment in g() clears f()'s taint. The inverse order would
// still cross-contaminate; that residual ceiling is documented in taint.go.)
func TestBuild_CrossFunctionNameReuseNotContaminated(t *testing.T) {
	f := &ir.IRNode{
		Kind:  ir.NodeKindFunction,
		Attrs: map[string]any{"function_name": "f"},
		Children: []*ir.IRNode{
			assignment("x", "request.args.get('id')", ident("_")),
		},
	}
	g := &ir.IRNode{
		Kind:  ir.NodeKindFunction,
		Attrs: map[string]any{"function_name": "g"},
		Children: []*ir.IRNode{
			assignment("x", "\"clean\"", &ir.IRNode{Kind: ir.NodeKindLiteral, Text: "clean"}),
		},
	}
	root := &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{f, g}}
	tainted := build(&ir.IRFile{Root: root, Language: core.LangPython})
	if tainted["x"] {
		t.Error("expected g's clean x to not be contaminated by f's tainted x")
	}
}

// TestBuildContext_SourcePatternReason verifies that a source-pattern match
// records the RHS text itself as the taint reason.
func TestBuildContext_SourcePatternReason(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("user_id", "request.args.get('id')", ident("_")),
		},
	}
	file := &ir.IRFile{Root: root}
	result := taint.BuildContext(file, symboltable.NewBuilder().Build(file), nil)
	if !result.Tainted["user_id"] {
		t.Fatal("expected user_id to be tainted")
	}
	if got := result.Reasons["user_id"]; got != "request.args.get('id')" {
		t.Errorf("Reasons[user_id] = %q, want the RHS source expression", got)
	}
}

// TestBuildContext_PropagationReason verifies that taint propagated from an
// already-tainted identifier records "propagated from <name>".
func TestBuildContext_PropagationReason(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("user_id", "request.args.get('id')", ident("_")),
			assignment("query", "\"SELECT \" + user_id", ident("user_id")),
		},
	}
	file := &ir.IRFile{Root: root}
	result := taint.BuildContext(file, symboltable.NewBuilder().Build(file), nil)
	if !result.Tainted["query"] {
		t.Fatal("expected query to be tainted")
	}
	if got, want := result.Reasons["query"], "propagated from user_id"; got != want {
		t.Errorf("Reasons[query] = %q, want %q", got, want)
	}
}

// TestBuildContext_SummaryCallReason verifies that taint from a same-file
// summarized function call records "tainted via <callee>(...)".
func TestBuildContext_SummaryCallReason(t *testing.T) {
	fn := &ir.IRNode{
		Kind:  ir.NodeKindFunction,
		Attrs: map[string]any{"function_name": "get_user"},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindReturn, Attrs: map[string]any{"return_expr": "request.args.get('id')"}},
		},
	}
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			fn,
			assignment("y", "get_user()", &ir.IRNode{
				Kind:     ir.NodeKindCall,
				Children: []*ir.IRNode{ident("get_user")},
			}),
		},
	}
	file := &ir.IRFile{Root: root, Language: core.LangPython}
	result := taint.BuildContext(file, symboltable.NewBuilder().Build(file), nil)
	if !result.Tainted["y"] {
		t.Fatal("expected y to be tainted")
	}
	if got, want := result.Reasons["y"], "tainted via get_user(...)"; got != want {
		t.Errorf("Reasons[y] = %q, want %q", got, want)
	}
}

// TestBuildContext_SanitizerClearsReason verifies that a sanitizer call
// clears both the taint verdict and any previously recorded reason.
func TestBuildContext_SanitizerClearsReason(t *testing.T) {
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("x", "request.args.get('y')", ident("_")),
			assignment("x", "html.escape(x)", &ir.IRNode{
				Kind:     ir.NodeKindCall,
				Children: []*ir.IRNode{ident("escape"), ident("x")},
			}),
		},
	}
	file := &ir.IRFile{Root: root, Language: core.LangPython}
	result := taint.BuildContext(file, symboltable.NewBuilder().Build(file), nil)
	if result.Tainted["x"] {
		t.Error("expected x to NOT be tainted after sanitizer")
	}
	if _, ok := result.Reasons["x"]; ok {
		t.Errorf("expected no stale reason for x after sanitizer, got %q", result.Reasons["x"])
	}
}

// TestBuildContext_AugmentedAssignmentKeepsReason verifies that an augmented
// assignment inheriting its previous true verdict also keeps the previously
// recorded reason instead of overwriting it with empty.
func TestBuildContext_AugmentedAssignmentKeepsReason(t *testing.T) {
	aug := assignment("x", "\" suffix\"", &ir.IRNode{Kind: ir.NodeKindLiteral, Text: " suffix"})
	aug.Attrs["augmented"] = true
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			assignment("x", "request.args.get('y')", ident("_")),
			aug,
		},
	}
	file := &ir.IRFile{Root: root, Language: core.LangPython}
	result := taint.BuildContext(file, symboltable.NewBuilder().Build(file), nil)
	if !result.Tainted["x"] {
		t.Fatal("expected x to stay tainted after augmented assignment")
	}
	if got, want := result.Reasons["x"], "request.args.get('y')"; got != want {
		t.Errorf("Reasons[x] = %q, want the original source reason %q preserved", got, want)
	}
}

// TestBuildContext_NilFile verifies BuildContext returns non-nil empty maps
// for a nil file, mirroring TestBuild_NilFile.
func TestBuildContext_NilFile(t *testing.T) {
	result := taint.BuildContext(nil, nil, nil)
	if len(result.Tainted) != 0 || len(result.Reasons) != 0 {
		t.Errorf("expected empty maps for nil file, got %v / %v", result.Tainted, result.Reasons)
	}
}

// TestBuild_NilSymbolTableDisablesInterprocedural: without a symbol table
// the summary step is skipped but direct source/propagation still works.
func TestBuild_NilSymbolTableDisablesInterprocedural(t *testing.T) {
	fn := &ir.IRNode{
		Kind:  ir.NodeKindFunction,
		Attrs: map[string]any{"function_name": "get_user"},
		Children: []*ir.IRNode{
			{Kind: ir.NodeKindReturn, Attrs: map[string]any{"return_expr": "request.args.get('id')"}},
		},
	}
	root := &ir.IRNode{
		Kind: ir.NodeKindModule,
		Children: []*ir.IRNode{
			fn,
			assignment("direct", "request.args.get('id')", ident("_")),
			assignment("y", "get_user()", &ir.IRNode{
				Kind:     ir.NodeKindCall,
				Children: []*ir.IRNode{ident("get_user")},
			}),
		},
	}
	tainted := taint.Build(&ir.IRFile{Root: root, Language: core.LangPython}, nil)
	if !tainted["direct"] {
		t.Error("expected direct source assignment to be tainted with nil symbols")
	}
	if tainted["y"] {
		t.Error("expected interprocedural step to be disabled with nil symbols")
	}
}
