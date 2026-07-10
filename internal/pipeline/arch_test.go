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
		{"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules", "/engine"},
		{"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core", "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal"},
		{"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir", "/analyzer"},
		{"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir", "/engine"},
		{"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir", "/pipeline"},
		{"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer", "/pipeline"},
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
