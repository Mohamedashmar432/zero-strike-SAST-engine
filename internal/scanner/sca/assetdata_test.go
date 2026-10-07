package sca

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// A package.json under public/ is a vendored asset's manifest, not the
// project's dependency list; AssetData entries are for the secrets scanner.
func TestSCAScanner_RejectsAssetData(t *testing.T) {
	s := New("warn")
	if s.Accepts(walker.FileEntry{Path: "public/vendor/package.json", AssetData: true}) {
		t.Error("SCA must not accept AssetData entries")
	}
	if !s.Accepts(walker.FileEntry{Path: "package.json"}) {
		t.Error("SCA must accept a root package.json")
	}
}
