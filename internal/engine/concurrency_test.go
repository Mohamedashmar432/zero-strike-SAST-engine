package engine_test

import (
	"context"
	"sync"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

// TestMatch_ConcurrentSharedIndex is the regression test for the scan
// non-determinism recorded but left unexplained in Sprint 25 ("one full
// directory scan missed a DES.new finding that six identical reruns found").
//
// The SAST scanner matches every file against one shared *Index across
// runtime.NumCPU() goroutines. Match used to seed its candidate list with
// `candidates := mc.Index.byKind[n.Kind]` and then append the byCallee
// matches onto it. That slice aliases the index's own backing array, so when
// byKind had spare capacity the append wrote straight into the shared index —
// workers overwrote each other's candidates and rules were skipped at random.
// Real scans of 12 fixtures returned 6 to 11 of 11 expected findings.
//
// This exercises the exact shape that triggers it: several rules in the
// byKind[call] bucket (so the slice has spare capacity from BuildIndex's
// appends) plus one in byCallee, matched concurrently.
//
// MUST RUN UNDER -race TO BE MEANINGFUL. Verified against the reintroduced
// bug: a plain `go test` run still passes (the corruption does not reliably
// change the match count at this fixture size — it took 12 real files and the
// full 410-rule index to move the count), while `go test -race` reports the
// write every time. CI runs the CGo leg with -race for exactly this reason;
// dropping that flag silently retires this test.
func TestMatch_ConcurrentSharedIndex(t *testing.T) {
	// Rules with kind:call and no callee land in byKind[call]; the repeated
	// appends inside BuildIndex leave that slice with cap > len, which is what
	// makes an append to it corrupt the index rather than copy.
	ruleList := []*rules.Rule{}
	for _, id := range []string{"ZS-TEST-A", "ZS-TEST-B", "ZS-TEST-C"} {
		argc := 1
		ruleList = append(ruleList, &rules.Rule{
			ID:       id,
			Language: core.LangPython,
			Match: rules.MatchPattern{
				Kind:    string(ir.NodeKindCall),
				Filters: []rules.Filter{{ArgumentCount: &argc}},
			},
		})
	}
	ruleList = append(ruleList, &rules.Rule{
		ID:       "ZS-TEST-CALLEE",
		Language: core.LangPython,
		Match: rules.MatchPattern{
			Kind:   string(ir.NodeKindCall),
			Callee: "eval",
		},
	})

	idx := engine.BuildIndex(ruleList)

	newCtx := func() *engine.MatchContext {
		call := &ir.IRNode{
			Kind: ir.NodeKindCall,
			Children: []*ir.IRNode{
				{Kind: ir.NodeKindIdentifier, Text: "eval"},
				{Kind: ir.NodeKindIdentifier, Text: "x"},
			},
			Attrs: map[string]any{"argument_count": 1},
		}
		return &engine.MatchContext{
			Index: idx,
			File: &analyzer.AnalysisResult{
				IR: &ir.IRFile{
					Language: core.LangPython,
					Path:     "t.py",
					Root:     &ir.IRNode{Kind: ir.NodeKindModule, Children: []*ir.IRNode{call}},
				},
			},
		}
	}

	eng := engine.New()
	baseline, err := eng.Match(context.Background(), newCtx())
	if err != nil {
		t.Fatalf("baseline Match: %v", err)
	}
	want := len(baseline)
	if want != len(ruleList) {
		t.Fatalf("baseline matched %d rules, want %d — fixture no longer exercises both buckets", want, len(ruleList))
	}

	const workers, iters = 8, 200
	var wg sync.WaitGroup
	bad := make(chan int, workers*iters)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				got, err := eng.Match(context.Background(), newCtx())
				if err != nil || len(got) != want {
					bad <- len(got)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(bad)
	if n, ok := <-bad; ok {
		t.Fatalf("concurrent Match returned %d rules, want %d — the shared rule index is being mutated", n, want)
	}
}
