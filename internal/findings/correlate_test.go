package findings_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
)

func sastFinding(ruleID, file, sourceVar string) core.Finding {
	f := core.Finding{
		RuleID:   ruleID,
		Kind:     core.FindingKindSAST,
		Location: core.Location{File: file, StartLine: 1},
	}
	if sourceVar != "" {
		f.TaintContext = &core.TaintContext{SourceVar: sourceVar}
	}
	return f
}

// TestCorrelate_LinksSameFileSameSource verifies that two SAST findings in the
// same file sharing a tainted source variable get identical chain metadata,
// while an unrelated finding in the same slice is left untouched.
func TestCorrelate_LinksSameFileSameSource(t *testing.T) {
	all := []core.Finding{
		sastFinding("ZS-PY-034", "app.py", "path"), // traversal read
		sastFinding("ZS-PY-013", "app.py", "path"), // cmd injection, same source
		sastFinding("ZS-PY-001", "app.py", ""),     // no taint context
		sastFinding("ZS-PY-034", "other.py", "path"), // same var, different file
	}

	findings.Correlate(all)

	for i := range 2 {
		md := all[i].Metadata
		if md == nil {
			t.Fatalf("finding %d: expected chain metadata, got nil", i)
		}
		if md[findings.MetaChainSize] != "2" {
			t.Errorf("finding %d: chain_size = %q, want 2", i, md[findings.MetaChainSize])
		}
		if md[findings.MetaChainSource] != "path" {
			t.Errorf("finding %d: chain_source = %q, want path", i, md[findings.MetaChainSource])
		}
		if md[findings.MetaChainRules] != "ZS-PY-013,ZS-PY-034" {
			t.Errorf("finding %d: chain_rules = %q, want sorted pair", i, md[findings.MetaChainRules])
		}
	}
	if all[0].Metadata[findings.MetaChainID] == "" ||
		all[0].Metadata[findings.MetaChainID] != all[1].Metadata[findings.MetaChainID] {
		t.Errorf("chain_id mismatch: %q vs %q",
			all[0].Metadata[findings.MetaChainID], all[1].Metadata[findings.MetaChainID])
	}

	if all[2].Metadata != nil {
		t.Errorf("untainted finding gained metadata: %v", all[2].Metadata)
	}
	if all[3].Metadata != nil {
		t.Errorf("different-file finding gained metadata: %v", all[3].Metadata)
	}
}

// TestCorrelate_SingletonNotChained verifies a lone tainted finding gets no
// chain metadata.
func TestCorrelate_SingletonNotChained(t *testing.T) {
	all := []core.Finding{sastFinding("ZS-GO-001", "main.go", "input")}
	findings.Correlate(all)
	if all[0].Metadata != nil {
		t.Errorf("singleton finding gained metadata: %v", all[0].Metadata)
	}
}
