package framework

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// scanClone writes a GitHub Actions workflow plus a Django .env into a fresh
// temp directory (standing in for a per-scan temp clone) and returns the
// fingerprint and displayed path of every finding keyed by rule+key.
func scanClone(t *testing.T) map[string][2]string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		".github/workflows/ci.yml": "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v3\n",
		"app/.env":                 "DEBUG=true\n",
	}
	var entries []walker.FileEntry
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, walker.FileEntry{Path: p})
	}
	fs, _, err := New(root).Scan(context.Background(), entries)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][2]string{}
	for _, f := range fs {
		out[f.RuleID+"|"+f.Config.Key] = [2]string{f.Fingerprint, f.Location.File}
	}
	return out
}

// Regression: config-finding fingerprints must not depend on the absolute scan
// root, or rescanning the same commit from another temp clone churns them.
func TestConfigFingerprintStableAcrossScanRoots(t *testing.T) {
	a, b := scanClone(t), scanClone(t)
	if len(a) < 2 {
		t.Fatalf("expected at least 2 config findings, got %d", len(a))
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			t.Fatalf("finding %s missing from second scan", k)
		}
		if va[0] != vb[0] {
			t.Errorf("%s: fingerprint differs across scan roots (%s vs %s)", k, va[0], vb[0])
		}
		if va[1] == vb[1] {
			t.Errorf("%s: displayed path should remain the absolute scan path", k)
		}
	}
}
