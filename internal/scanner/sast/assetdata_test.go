//go:build cgo

package sast

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// AssetData entries (data files under static/public/assets) exist only for
// the secrets scanner; SAST must keep rejecting them so the asset-dir skip
// stays an FP control. See walker.FileEntry.AssetData.
func TestSASTScanner_RejectsAssetData(t *testing.T) {
	s := &SASTScanner{}
	if s.Accepts(walker.FileEntry{Path: "public/config.json", AssetData: true}) {
		t.Error("SAST must not accept AssetData entries")
	}
	if !s.Accepts(walker.FileEntry{Path: "app.py"}) {
		t.Error("SAST must accept ordinary source files")
	}
}
