package pipeline_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// TestImportDAG verifies the dependency direction invariant (C7):
//
//	cmd → pipeline → { engine → analyzer → ir ← parser, findings, report }
//	core imports nothing; rules never imports engine.
func TestImportDAG(t *testing.T) {
	cases := []struct{ pkg, mustNotContain string }{
		{"github.com/zerostrike/scanner/internal/rules", "/engine"},
		{"github.com/zerostrike/scanner/internal/core", "github.com/zerostrike/scanner/internal"},
		{"github.com/zerostrike/scanner/internal/ir", "/analyzer"},
		{"github.com/zerostrike/scanner/internal/ir", "/engine"},
		{"github.com/zerostrike/scanner/internal/ir", "/pipeline"},
		{"github.com/zerostrike/scanner/internal/analyzer", "/pipeline"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.pkg+" !→ "+tc.mustNotContain, func(t *testing.T) {
			out, err := exec.Command("go", "list", "-json", tc.pkg).Output()
			if err != nil {
				t.Skipf("go list %s: %v", tc.pkg, err)
				return
			}
			var result struct{ Imports []string }
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatalf("unmarshal go list output: %v", err)
			}
			for _, imp := range result.Imports {
				if strings.Contains(imp, tc.mustNotContain) {
					t.Errorf("%s imports %q (DAG invariant violation: must not contain %q)", tc.pkg, imp, tc.mustNotContain)
				}
			}
		})
	}
}
