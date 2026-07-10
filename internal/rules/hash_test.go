// SPDX-License-Identifier: Apache-2.0
package rules_test

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
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

	// The flat "." shape must be just as content/add-sensitive as the nested
	// data/<lang> shape already covered above — this is the exact call the
	// real --rules flag makes, so it deserves its own sensitivity check
	// rather than only a non-empty-hash smoke test.
	changed := fstest.MapFS{
		"custom-rule.yaml": &fstest.MapFile{Data: []byte("id: custom-rule\nseverity: critical\n")},
	}
	hChanged, err := rules.HashRuleSet(changed, []string{"."})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	if h == hChanged {
		t.Fatal("expected a content change in the flat directory to alter the hash")
	}

	withExtra := fstest.MapFS{
		"custom-rule.yaml":  &fstest.MapFile{Data: []byte("id: custom-rule\nseverity: high\n")},
		"another-rule.yaml": &fstest.MapFile{Data: []byte("id: another-rule\nseverity: low\n")},
	}
	hExtra, err := rules.HashRuleSet(withExtra, []string{"."})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	if h == hExtra {
		t.Fatal("expected an added file in the flat directory to alter the hash")
	}
}

func TestHashRuleSet_CRLFNormalizedToLF(t *testing.T) {
	// This repo has no .gitattributes pinning rule YAML line endings, and a
	// Windows checkout with core.autocrlf=true produces CRLF where a Linux
	// CI runner produces LF for the same commit's content — go:embed bakes
	// in whatever bytes are on disk at build time. HashRuleSet must not
	// treat these as different content, or the cache would spuriously
	// invalidate every time the team rebuilds on a different platform.
	lf := fstest.MapFS{
		"data/python/rule.yaml": &fstest.MapFile{Data: []byte("id: x\nseverity: high\n")},
	}
	crlf := fstest.MapFS{
		"data/python/rule.yaml": &fstest.MapFile{Data: []byte("id: x\r\nseverity: high\r\n")},
	}

	hLF, err := rules.HashRuleSet(lf, []string{"data/python"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	hCRLF, err := rules.HashRuleSet(crlf, []string{"data/python"})
	if err != nil {
		t.Fatalf("HashRuleSet: %v", err)
	}
	if hLF != hCRLF {
		t.Fatalf("expected CRLF and LF variants of identical content to hash identically, got %s vs %s", hLF, hCRLF)
	}
}

// erroringFS wraps an fstest.MapFS but returns a non-ErrNotExist error for a
// specific directory, simulating a real I/O failure (e.g. a permission
// error) as distinct from "directory doesn't exist."
type erroringFS struct {
	fstest.MapFS
	failDir string
	err     error
}

func (e erroringFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == e.failDir {
		return nil, e.err
	}
	return e.MapFS.ReadDir(name)
}

func TestHashRuleSet_RealReadErrorIsPropagatedNotSkipped(t *testing.T) {
	fsys := erroringFS{
		MapFS:   mapFS(),
		failDir: "data/python",
		err:     fs.ErrPermission,
	}

	_, err := rules.HashRuleSet(fsys, []string{"data/python", "data/js"})
	if err == nil {
		t.Fatal("expected a real read error to be propagated, got nil")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a permission error must not be mistaken for a missing directory, got: %v", err)
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
