package sast

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/ir"
)

// These tests exercise only the parser-independent caching helpers
// (caching.go), which carries no //go:build tag. They run in CGo-less
// environments/CI where sast.go (cgo-only, links tree-sitter parsers) can't
// even be compiled, let alone let us construct a real SASTScanner and drive
// processFile end-to-end.
//
// TODO(cgo-capable CI, once a real cache.FindingCache/cache.ASTCache is
// wired in by the pipeline-level task): add an integration test in
// sast.go's own build (cgo-tagged) that runs processFile twice against the
// same real file with a real DiskCache/DiskASTCache — cold, then warm — and
// asserts identical []core.Finding on both runs. This is the one property
// (hit-path control flow, and that analysis behaves identically on a
// cache-rebuilt tree vs. a freshly-parsed one) that cannot be verified in a
// no-CGo environment and is currently only verified by code review.

func TestSha256Hex(t *testing.T) {
	data := []byte("package main\n")
	got := sha256Hex(data)

	want := sha256.Sum256(data)
	wantHex := hex.EncodeToString(want[:])
	if got != wantHex {
		t.Fatalf("sha256Hex(%q) = %q, want %q", data, got, wantHex)
	}

	if len(got) != 64 {
		t.Fatalf("sha256Hex length = %d, want 64 (hex-encoded 32 bytes)", len(got))
	}

	// Same input must always produce the same key.
	if got2 := sha256Hex(data); got2 != got {
		t.Fatalf("sha256Hex is not deterministic: %q != %q", got, got2)
	}

	// Different input must (in practice) produce a different key.
	if other := sha256Hex([]byte("different content")); other == got {
		t.Fatalf("sha256Hex produced the same digest for different content")
	}
}

// buildSampleIR constructs a small, hand-built IR tree without going through
// any tree-sitter-backed parser builder, so it works without CGo.
func buildSampleIR() *ir.IRFile {
	child := &ir.IRNode{
		NodeID: "child-1",
		Kind:   ir.NodeKindCall,
		Text:   "os.Getenv(\"X\")",
		Location: core.Location{
			File: "sample.go", StartLine: 2, EndLine: 2,
		},
		Attrs: map[string]any{
			"argument_count": 1,
			"parameters":     []string{"X"},
		},
	}
	root := &ir.IRNode{
		NodeID:   "root",
		Kind:     ir.NodeKindModule,
		Text:     "",
		Location: core.Location{File: "sample.go", StartLine: 1, EndLine: 3},
		Children: []*ir.IRNode{child},
	}
	child.Parent = root

	return &ir.IRFile{
		Language: core.LangGo,
		Path:     "sample.go",
		Root:     root,
	}
}

func TestEncodeDecodeIR_RoundTrip(t *testing.T) {
	original := buildSampleIR()

	data, ok := encodeIR(original)
	if !ok {
		t.Fatalf("encodeIR reported ok=false for a well-formed IR file")
	}
	if len(data) == 0 {
		t.Fatalf("encodeIR returned empty data")
	}

	rebuilt, ok := decodeCachedIR(data, original.Language, original.Path)
	if !ok {
		t.Fatalf("decodeCachedIR reported ok=false for data produced by encodeIR")
	}

	if rebuilt.Language != original.Language {
		t.Errorf("rebuilt.Language = %v, want %v", rebuilt.Language, original.Language)
	}
	if rebuilt.Path != original.Path {
		t.Errorf("rebuilt.Path = %q, want %q", rebuilt.Path, original.Path)
	}
	if rebuilt.Root == nil {
		t.Fatalf("rebuilt.Root is nil")
	}
	if rebuilt.Root.Kind != ir.NodeKindModule {
		t.Errorf("rebuilt.Root.Kind = %v, want %v", rebuilt.Root.Kind, ir.NodeKindModule)
	}
	if len(rebuilt.Root.Children) != 1 {
		t.Fatalf("rebuilt.Root.Children = %d, want 1", len(rebuilt.Root.Children))
	}

	gotChild := rebuilt.Root.Children[0]
	if gotChild.Text != "os.Getenv(\"X\")" {
		t.Errorf("child.Text = %q, want %q", gotChild.Text, "os.Getenv(\"X\")")
	}
	if gotChild.Parent != rebuilt.Root {
		t.Errorf("child.Parent not wired back to rebuilt root")
	}

	// argument_count must survive the JSON round trip as an int, not float64
	// (see ir.RebuildIR's restoreAttrs doc comment).
	if ac, ok := gotChild.Attrs["argument_count"].(int); !ok || ac != 1 {
		t.Errorf("child.Attrs[\"argument_count\"] = %#v, want int(1)", gotChild.Attrs["argument_count"])
	}
	// parameters must survive as []string, not []interface{}.
	if params, ok := gotChild.Attrs["parameters"].([]string); !ok || len(params) != 1 || params[0] != "X" {
		t.Errorf("child.Attrs[\"parameters\"] = %#v, want []string{\"X\"}", gotChild.Attrs["parameters"])
	}
}

func TestDecodeCachedIR_CorruptedData(t *testing.T) {
	// Not valid JSON at all.
	if _, ok := decodeCachedIR([]byte("not json"), core.LangGo, "sample.go"); ok {
		t.Fatalf("decodeCachedIR reported ok=true for garbage bytes, want ok=false")
	}

	// Valid JSON, but not the []ir.SerialNode shape (unmarshals into a
	// non-empty-but-wrong structure, or unmarshals into an empty slice).
	if _, ok := decodeCachedIR([]byte(`{"foo":"bar"}`), core.LangGo, "sample.go"); ok {
		t.Fatalf("decodeCachedIR reported ok=true for a JSON object, want ok=false")
	}

	// Valid JSON array, but empty -> RebuildIR returns nil for len(nodes)==0.
	if _, ok := decodeCachedIR([]byte(`[]`), core.LangGo, "sample.go"); ok {
		t.Fatalf("decodeCachedIR reported ok=true for an empty node list, want ok=false")
	}
}

func TestEncodeIR_NilFile(t *testing.T) {
	if data, ok := encodeIR(nil); ok || data != nil {
		t.Fatalf("encodeIR(nil) = (%v, %v), want (nil, false)", data, ok)
	}
}
