package walker_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

// collectWalk drains both channels returned by Walk and returns the discovered
// paths together with any errors.
func collectWalk(t *testing.T, w walker.Walker, root string) ([]string, []error) {
	t.Helper()
	entries, errs := w.Walk(root)

	var paths []string
	var walkErrs []error

	for {
		select {
		case e, ok := <-entries:
			if !ok {
				entries = nil
			} else {
				paths = append(paths, e.Path)
			}
		case err, ok := <-errs:
			if !ok {
				errs = nil
			} else {
				walkErrs = append(walkErrs, err)
			}
		}
		if entries == nil && errs == nil {
			break
		}
	}
	sort.Strings(paths)
	return paths, walkErrs
}

// writeFile creates parent directories as needed and writes content to path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// makeTempDir creates a temp directory that is cleaned up after the test.
func makeTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "walker-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestWalk_EmptyDir(t *testing.T) {
	root := makeTempDir(t)
	w := walker.NewWalker(nil)

	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if len(paths) != 0 {
		t.Errorf("expected 0 files, got %d: %v", len(paths), paths)
	}
}

func TestWalk_FindsFiles(t *testing.T) {
	root := makeTempDir(t)
	want := []string{
		filepath.Join(root, "a.py"),
		filepath.Join(root, "b.py"),
		filepath.Join(root, "c.py"),
	}
	for _, p := range want {
		writeFile(t, p, "# python")
	}
	sort.Strings(want)

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != len(want) {
		t.Fatalf("expected %d files, got %d: %v", len(want), len(paths), paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("paths[%d]: want %q, got %q", i, want[i], paths[i])
		}
	}
}

func TestWalk_SkipsGitDir(t *testing.T) {
	root := makeTempDir(t)
	writeFile(t, filepath.Join(root, ".git", "secret.py"), "# should not appear")
	writeFile(t, filepath.Join(root, "main.py"), "# should appear")

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(paths), paths)
	}
	if paths[0] != filepath.Join(root, "main.py") {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestWalk_SkipsNodeModules(t *testing.T) {
	root := makeTempDir(t)
	writeFile(t, filepath.Join(root, "node_modules", "index.js"), "// skipped")
	writeFile(t, filepath.Join(root, "app.js"), "// kept")

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(paths), paths)
	}
	if paths[0] != filepath.Join(root, "app.js") {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestWalk_SkipsBinaryExtension(t *testing.T) {
	root := makeTempDir(t)
	writeFile(t, filepath.Join(root, "tool.exe"), "binary")
	writeFile(t, filepath.Join(root, "script.py"), "# source")

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(paths), paths)
	}
	if paths[0] != filepath.Join(root, "script.py") {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestWalk_SkipsLargeFile(t *testing.T) {
	root := makeTempDir(t)

	// Create a file just over 1 MB.
	largePath := filepath.Join(root, "large.py")
	data := make([]byte, 1<<20+1) // 1 MB + 1 byte
	if err := os.WriteFile(largePath, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	writeFile(t, filepath.Join(root, "small.py"), "# tiny")

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(paths), paths)
	}
	if paths[0] != filepath.Join(root, "small.py") {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestWalk_RespectsGitignore(t *testing.T) {
	root := makeTempDir(t)
	writeFile(t, filepath.Join(root, ".gitignore"), "secrets.py\n")
	writeFile(t, filepath.Join(root, "secrets.py"), "# ignored")
	writeFile(t, filepath.Join(root, "main.py"), "# kept")
	writeFile(t, filepath.Join(root, "util.py"), "# kept")

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	// secrets.py must not be present; main.py and util.py must be.
	for _, p := range paths {
		if filepath.Base(p) == "secrets.py" {
			t.Errorf("secrets.py should have been ignored but was emitted: %q", p)
		}
	}

	wantCount := 2
	// .gitignore itself has no extension recognised as source — it is emitted.
	// Adjust expectation: .gitignore has no skipped ext so it will be emitted too.
	// Recalculate: we wrote .gitignore, secrets.py, main.py, util.py.
	// After filtering: secrets.py ignored → .gitignore, main.py, util.py remain.
	wantCount = 3
	if len(paths) != wantCount {
		t.Fatalf("expected %d files, got %d: %v", wantCount, len(paths), paths)
	}
}

func TestWalk_SkipsStaticDir(t *testing.T) {
	root := makeTempDir(t)
	writeFile(t, filepath.Join(root, "static", "jquery.min.js"), "eval('bad')")
	writeFile(t, filepath.Join(root, "app.py"), "# kept")

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 file (app.py), got %d: %v", len(paths), paths)
	}
	if filepath.Base(paths[0]) != "app.py" {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestWalk_SkipsMinifiedJsByDefault(t *testing.T) {
	root := makeTempDir(t)
	writeFile(t, filepath.Join(root, "Scripts", "jquery-1.3.2.min.js"), "// vendored, noisy")
	writeFile(t, filepath.Join(root, "Scripts", "app.js"), "// first-party")

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 file (app.js), got %d: %v", len(paths), paths)
	}
	if filepath.Base(paths[0]) != "app.js" {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestWalk_ExcludeDirOption(t *testing.T) {
	root := makeTempDir(t)
	writeFile(t, filepath.Join(root, "gen", "schema.go"), "// generated")
	writeFile(t, filepath.Join(root, "main.go"), "// kept")

	w := walker.NewWalker(&walker.Options{ExcludeDirs: []string{"gen"}})
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 file (main.go), got %d: %v", len(paths), paths)
	}
	if filepath.Base(paths[0]) != "main.go" {
		t.Errorf("unexpected path: %q", paths[0])
	}
}

func TestWalk_SubdirectoryRecursion(t *testing.T) {
	root := makeTempDir(t)
	files := []string{
		filepath.Join(root, "a.py"),
		filepath.Join(root, "sub", "b.py"),
		filepath.Join(root, "sub", "deep", "c.py"),
	}
	for _, f := range files {
		writeFile(t, f, "# python")
	}
	sort.Strings(files)

	w := walker.NewWalker(nil)
	paths, errs := collectWalk(t, w, root)

	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(paths) != len(files) {
		t.Fatalf("expected %d files, got %d: %v", len(files), len(paths), paths)
	}
	for i := range files {
		if paths[i] != files[i] {
			t.Errorf("paths[%d]: want %q, got %q", i, files[i], paths[i])
		}
	}
}
