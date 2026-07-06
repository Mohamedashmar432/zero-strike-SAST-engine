// SPDX-License-Identifier: Apache-2.0
package rules_test

import (
	"testing"
	"testing/fstest"

	"github.com/zerostrike/scanner/internal/rules"
)

func mapFS() fstest.MapFS {
	return fstest.MapFS{
		"data/python/sql-injection.yaml": &fstest.MapFile{Data: []byte("id: python-sql-injection\nseverity: high\n")},
		"data/python/xss.yaml":           &fstest.MapFile{Data: []byte("id: python-xss\nseverity: medium\n")},
		"data/js/eval.yaml":              &fstest.MapFile{Data: []byte("id: js-eval\nseverity: high\n")},
		"data/js/notes.txt":              &fstest.MapFile{Data: []byte("not a rule file, must be ignored")},
	}
}

func TestHashRuleSet_DeterministicSameContent(t *testing.T) {
	fsys := mapFS()
	dirs := []string{"data/python", "data/js"}

	h1, err := rules.HashRuleSet(fsys, dirs)
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	h2, err := rules.HashRuleSet(fsys, dirs)
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected identical hashes for identical content, got %s vs %s", h1, h2)
	}
	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestHashRuleSet_ContentChangeAltersHash(t *testing.T) {
	dirs := []string{"data/python", "data/js"}

	fsys1 := mapFS()
	h1, err := rules.HashRuleSet(fsys1, dirs)
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}

	fsys2 := mapFS()
	// Flip a single byte's worth of content in one rule file.
	fsys2["data/python/sql-injection.yaml"] = &fstest.MapFile{
		Data: []byte("id: python-sql-injection\nseverity: critical\n"),
	}
	h2, err := rules.HashRuleSet(fsys2, dirs)
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}

	if h1 == h2 {
		t.Fatal("expected different hashes after a content change, got identical hashes")
	}
}

func TestHashRuleSet_FileAddedOrRemovedAltersHash(t *testing.T) {
	dirs := []string{"data/python", "data/js"}

	fsys1 := mapFS()
	h1, err := rules.HashRuleSet(fsys1, dirs)
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}

	fsys2 := mapFS()
	fsys2["data/python/new-rule.yaml"] = &fstest.MapFile{Data: []byte("id: python-new-rule\nseverity: low\n")}
	h2, err := rules.HashRuleSet(fsys2, dirs)
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}

	if h1 == h2 {
		t.Fatal("expected different hashes after adding a rule file, got identical hashes")
	}
}

func TestHashRuleSet_OrderIndependent(t *testing.T) {
	fsys := mapFS()

	h1, err := rules.HashRuleSet(fsys, []string{"data/python", "data/js"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	h2, err := rules.HashRuleSet(fsys, []string{"data/js", "data/python"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("expected hash to be independent of dirs ordering, got %s vs %s", h1, h2)
	}
}

func TestHashRuleSet_IgnoresNonYAMLFiles(t *testing.T) {
	withTxt := mapFS()

	withoutTxt := mapFS()
	delete(withoutTxt, "data/js/notes.txt")

	h1, err := rules.HashRuleSet(withTxt, []string{"data/python", "data/js"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	h2, err := rules.HashRuleSet(withoutTxt, []string{"data/python", "data/js"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("expected non-yaml files to be ignored, got different hashes %s vs %s", h1, h2)
	}
}

func TestHashRuleSet_MissingDirectorySkippedGracefully(t *testing.T) {
	fsys := mapFS()

	// A dir that doesn't exist in fsys at all (e.g. an external --rules
	// override that doesn't supply every language) must not error.
	if _, err := rules.HashRuleSet(fsys, []string{"data/python", "data/does-not-exist"}); err != nil {
		t.Fatalf("expected missing directory to be skipped gracefully, got error: %v", err)
	}

	// Confirm it produces the same hash as if the missing dir were simply
	// omitted from the list.
	h1, err := rules.HashRuleSet(fsys, []string{"data/python", "data/does-not-exist"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	h2, err := rules.HashRuleSet(fsys, []string{"data/python"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	if h1 != h2 {
		t.Fatal("expected missing directory to contribute nothing to the hash")
	}
}

func TestHashRuleSet_FlatDirectoryLikeExternalRulesOverride(t *testing.T) {
	// Mirrors how internal/pipeline/scanner.go loads an external --rules
	// directory: loader.LoadDir(".") on os.DirFS(cfg.RulesDir), i.e. a flat
	// directory rather than a data/<lang> layout.
	fsys := fstest.MapFS{
		"custom-rule.yaml": &fstest.MapFile{Data: []byte("id: custom-rule\nseverity: high\n")},
	}

	h, err := rules.HashRuleSet(fsys, []string{"."})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash for flat external rules directory")
	}
}

// TestHashRuleSet_EmbeddedRuleSetSanityCheck is an integration-style check
// against the real embedded rule set (not the synthetic MapFS fixtures
// above), confirming HashRuleSet works against rules.EmbeddedFS /
// rules.RuleDirs — the exact call the pipeline will eventually make.
func TestHashRuleSet_EmbeddedRuleSetSanityCheck(t *testing.T) {
	h, err := rules.HashRuleSet(rules.EmbeddedFS, rules.RuleDirs)
	if err != nil {
		t.Fatalf("HashRuleSet(EmbeddedFS, RuleDirs): %v", err)
	}
	if h == "" {
		t.Fatal("expected non-empty hash for embedded rule set")
	}
	if len(h) != 64 { // sha256 hex digest length
		t.Fatalf("expected a 64-char hex sha256 digest, got %d chars: %q", len(h), h)
	}
}
