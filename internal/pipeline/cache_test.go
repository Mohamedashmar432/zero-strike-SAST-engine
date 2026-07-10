package pipeline_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/cache"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/pipeline"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/version"
)

// testRuleYAML is a minimal valid rule fixture (same shape as
// internal/rules/loader_test.go's TestLoader_LoadsRationale fixture) that
// passes rules.NewValidator(): kind=call requires a callee, and the
// severity/confidence values must be in the validator's allowed sets.
const testRuleYAML = `id: ZS-TEST-001
name: Test Rule
version: "1.0.0"
language: python
category: dangerous-functions
severity: high
confidence: high
lifecycle: released
description: |
  Test description.
message: "Test message"
match:
  kind: call
  callee: eval
fix_suggestion: "Use something safer."
rationale: |
  Calling eval() on untrusted input lets an attacker execute arbitrary
  code in the context of the application.
`

func readMeta(t *testing.T, path string) cache.Meta {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read meta.json: %v", err)
	}
	var m cache.Meta
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal meta.json: %v", err)
	}
	return m
}

// TestPipelineNew_NoCache_NeverCreatesCacheDir locks in --no-cache's
// contract at the pipeline level: no .zerostrike directory should ever
// touch disk when caching is disabled.
func TestPipelineNew_NoCache_NeverCreatesCacheDir(t *testing.T) {
	root := t.TempDir()

	if _, err := pipeline.New(pipeline.ScanConfig{
		RootPath: root,
		NoCache:  true,
	}); err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}

	if _, statErr := os.Stat(filepath.Join(root, ".zerostrike")); !os.IsNotExist(statErr) {
		t.Fatalf("expected .zerostrike to never be created with NoCache=true, stat err=%v", statErr)
	}
}

// TestPipelineNew_Cache_CreatesMetaJSON verifies that, by default (NoCache
// false), pipeline.New opens a real on-disk cache under
// <root>/.zerostrike/cache and stamps it with the current engine/format/IR
// versions plus a non-empty rule-set hash.
func TestPipelineNew_Cache_CreatesMetaJSON(t *testing.T) {
	root := t.TempDir()

	if _, err := pipeline.New(pipeline.ScanConfig{RootPath: root}); err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}

	metaPath := filepath.Join(root, ".zerostrike", "cache", "meta.json")
	meta := readMeta(t, metaPath)

	if meta.EngineVersion != version.Version {
		t.Errorf("EngineVersion = %q, want %q", meta.EngineVersion, version.Version)
	}
	if meta.IRSchemaVersion != ir.SchemaVersion {
		t.Errorf("IRSchemaVersion = %d, want %d", meta.IRSchemaVersion, ir.SchemaVersion)
	}
	if meta.FormatVersion != cache.FormatVersion {
		t.Errorf("FormatVersion = %d, want %d", meta.FormatVersion, cache.FormatVersion)
	}
	if meta.RuleSetHash == "" {
		t.Error("expected non-empty RuleSetHash")
	}
}

// TestPipelineNew_RuleSetHashSensitivity_WipesFindingsNotIR proves that a
// rule-set change flows all the way through pipeline.New into a real
// findings/-only cache wipe (ir/ survives), not merely that HashRuleSet
// returns different digests for different inputs in isolation (already
// covered by internal/rules' own tests) or that cache.Open's invalidation
// table is correct in isolation (already covered by
// internal/cache/meta_test.go). This test additionally proves the PIPELINE
// computes and passes through the hash that makes that invariant fire.
func TestPipelineNew_RuleSetHashSensitivity_WipesFindingsNotIR(t *testing.T) {
	root := t.TempDir()

	// First pipeline: default embedded rules.
	if _, err := pipeline.New(pipeline.ScanConfig{RootPath: root}); err != nil {
		t.Fatalf("pipeline.New (embedded rules): %v", err)
	}

	metaPath := filepath.Join(root, ".zerostrike", "cache", "meta.json")
	meta1 := readMeta(t, metaPath)

	// Seed dummy files directly into findings/ and ir/ to prove the second
	// pipeline.New call selectively wipes only findings/.
	findingsDir := filepath.Join(root, ".zerostrike", "cache", "findings")
	irDir := filepath.Join(root, ".zerostrike", "cache", "ir")
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		t.Fatalf("mkdir findings: %v", err)
	}
	if err := os.MkdirAll(irDir, 0o755); err != nil {
		t.Fatalf("mkdir ir: %v", err)
	}
	dummyFindings := filepath.Join(findingsDir, "dummy.txt")
	dummyIR := filepath.Join(irDir, "dummy.txt")
	if err := os.WriteFile(dummyFindings, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write dummy findings file: %v", err)
	}
	if err := os.WriteFile(dummyIR, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write dummy ir file: %v", err)
	}

	// Second pipeline: same RootPath (same .zerostrike/cache), but a custom
	// rules dir with different rule content -> a different rule-set hash.
	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "ZS-TEST-001.yaml"), []byte(testRuleYAML), 0o644); err != nil {
		t.Fatalf("write test rule fixture: %v", err)
	}

	if _, err := pipeline.New(pipeline.ScanConfig{RootPath: root, RulesDir: rulesDir}); err != nil {
		t.Fatalf("pipeline.New (custom rules): %v", err)
	}

	meta2 := readMeta(t, metaPath)

	if meta1.RuleSetHash == meta2.RuleSetHash {
		t.Fatal("expected RuleSetHash to differ between embedded and custom rule sets")
	}

	if _, err := os.Stat(dummyFindings); !os.IsNotExist(err) {
		t.Errorf("expected findings/ dummy file to be wiped on a RuleSetHash mismatch, stat err=%v", err)
	}
	if _, err := os.Stat(dummyIR); err != nil {
		t.Errorf("expected ir/ dummy file to SURVIVE a RuleSetHash-only mismatch, but got stat err=%v", err)
	}
}

// TestPipelineNew_CacheOpenFailure_DegradesGracefully verifies that when
// cache.Open fails (here: RootPath/.zerostrike already exists as a regular
// FILE, so os.MkdirAll can't create RootPath/.zerostrike/cache underneath
// it), pipeline.New still succeeds - caching is a strictly optional
// performance optimization, not a scan precondition.
func TestPipelineNew_CacheOpenFailure_DegradesGracefully(t *testing.T) {
	root := t.TempDir()

	// Block .zerostrike from ever being a directory.
	if err := os.WriteFile(filepath.Join(root, ".zerostrike"), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("seed blocking file: %v", err)
	}

	if _, err := pipeline.New(pipeline.ScanConfig{RootPath: root}); err != nil {
		t.Fatalf("expected pipeline.New to degrade gracefully on a cache-open failure, got error: %v", err)
	}

	// os.IsNotExist only matches ENOENT. Here .zerostrike is a file, not a
	// dir, so stat(".zerostrike/cache") returns ENOTDIR on Linux (though
	// ENOENT on Windows) - either way, the path isn't a real directory.
	if _, statErr := os.Stat(filepath.Join(root, ".zerostrike", "cache")); statErr == nil {
		t.Errorf("expected no cache dir to be created when cache.Open fails, stat succeeded")
	}
}
