package walker_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// A one-line bundle outside any asset directory is third-party output; a
// hand-written script of ordinary line length is still scanned.
func TestPrecisionG2_MinifiedBundleOutsideAssetDirIsSkipped(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "WebContent", "swagger")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := "(function(){" + strings.Repeat("var a=document.body;", 100) + "})();"
	files := map[string]string{
		"bundle.js": bundle,
		"app.js":    "function f() {\n  return 1;\n}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths, _ := collectWalk(t, walker.NewWalker(nil), root)
	var gotBundle, gotApp bool
	for _, p := range paths {
		gotBundle = gotBundle || filepath.Base(p) == "bundle.js"
		gotApp = gotApp || filepath.Base(p) == "app.js"
	}
	if gotBundle {
		t.Error("a minified one-line bundle must not be walked")
	}
	if !gotApp {
		t.Error("a normal script must still be walked")
	}
}
